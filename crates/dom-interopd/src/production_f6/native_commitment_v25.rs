//! Explicit solver post-commit statement, never a transport ACK or inventory
//! capability. The solver producer reads its real committed inventory; the
//! initiator authenticates the ORIGINAL solver Relay envelope. Remote receipt
//! proves what that solver signed, not remote database access or a fresh F7
//! authorization. Funding still requires current local custody/time/role gates.
//! The certificate travels as an explicitly versioned QUOTE confirmation:
//! D-019 permits solver QUOTE, never solver ACCEPTANCE. That policy is unchanged.

use super::native_acceptance_v25::{
    NATIVE_INITIATOR_RECEIPTS_DOMAIN_V25, NATIVE_SOLVER_RECEIPTS_DOMAIN_V25,
};
use super::*;
use f6_engine::v2::AcceptedBindingAuthorityV2;
use rfq::native_reconfirmation_v25::{NativeAcceptanceV25, MAX_NATIVE_ACCEPTANCE_BYTES_V25};

pub(crate) const NATIVE_COMMITMENT_MAGIC_V25: &[u8; 8] = b"DOMFCM25";
pub(crate) const NATIVE_COMMITMENT_MESSAGE_TYPE_V25: u16 = relay::auth::message_type::QUOTE;
const DOMAIN: &[u8] = b"DOM-INTEROP/F6/NATIVE-SOLVER-POST-COMMIT/V25\0";
const ACCEPTED_DOMAIN: &[u8] = b"DOM-INTEROP/F6/NATIVE-ACCEPTED-DELIVERY/V25\0";
const ACCEPTED_NAMESPACE: &[u8] = b"interopd-f6-native-accepted-delivery-v25";
const OUTBOUND_NAMESPACE: &[u8] = b"interopd-f6-native-commitment-outbound-v25";
const REMOTE_NAMESPACE: &[u8] = b"interopd-f6-native-commitment-remote-v25";
const MAX_CERTIFICATE_BYTES: usize = 4096;
const MAX_ACCEPTED_RECORD_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeAcceptanceReceiptRoleV25 {
    Initiator,
    Solver,
}

/// Data only. Decoding does not authenticate the claimed commit or actor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeCommitmentCertificateV25 {
    wire: RouteWireContextV1,
    acceptance: NativeAcceptanceV25,
    acceptance_envelope: Digest32,
    acceptance_sequence: u64,
    selection_inputs: Digest32,
    binding_evidence: Digest32,
    committed_state: Digest32,
    committed_revision: u64,
    execution_fence: u64,
}

/// Only the local solver's checked real inventory producer issues this owner.
/// Bytes must be signed through the existing solver Relay/identity owner.
pub(crate) struct PreparedNativeCommitmentV25 {
    certificate: NativeCommitmentCertificateV25,
}

impl PreparedNativeCommitmentV25 {
    pub(crate) fn payload(&self) -> Result<Vec<u8>, ProductionF6ErrorV2> {
        self.certificate.canonical_bytes()
    }
}

/// An authenticated remote solver statement, NOT CommittedInventoryCapability.
/// Its scope is immutable; it is not a cached current-time/funding permit.
pub(crate) struct VerifiedNativeCommitmentV25 {
    certificate: NativeCommitmentCertificateV25,
    solver_envelope: Digest32,
    solver_sequence: u64,
}

/// Original solver statement AND its completed local Applied receipt. This is
/// historical agreement evidence only; it must not replace fresh funding gates.
pub(crate) struct RetainedNativeCommitmentV25 {
    verified: VerifiedNativeCommitmentV25,
}

impl RetainedNativeCommitmentV25 {
    pub(crate) fn statement(&self) -> &VerifiedNativeCommitmentV25 {
        &self.verified
    }
}

impl VerifiedNativeCommitmentV25 {
    pub(crate) fn certificate_digest(&self) -> Result<Digest32, ProductionF6ErrorV2> {
        self.certificate.digest()
    }
    pub(crate) fn acceptance_digest(&self) -> Result<Digest32, ProductionF6ErrorV2> {
        self.certificate
            .acceptance
            .message_digest()
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)
    }
    pub(crate) const fn wire(&self) -> RouteWireContextV1 {
        self.certificate.wire
    }
    pub(crate) const fn acceptance(&self) -> &NativeAcceptanceV25 {
        &self.certificate.acceptance
    }
}

struct RetainedAcceptanceV25 {
    acceptance: NativeAcceptanceV25,
    envelope: Digest32,
    sequence: u64,
    applied_receipt: Vec<u8>,
}

impl NativeCommitmentCertificateV25 {
    fn validate(&self) -> Result<(), ProductionF6ErrorV2> {
        let acceptance = &self.acceptance;
        let terms = acceptance.terms();
        if [
            self.wire.network_id,
            self.wire.route_id,
            self.wire.session_id,
            self.wire.roster_snapshot,
            self.acceptance_envelope,
            self.selection_inputs,
            self.binding_evidence,
            self.committed_state,
        ]
        .contains(&ZERO_DIGEST)
            || self.wire.policy_version == 0
            || self.committed_revision == 0
            || self.execution_fence == 0
            || acceptance.session_id() != self.wire.session_id
            || terms.bond_policy_version != self.wire.policy_version
        {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        acceptance
            .canonical_bytes()
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        Ok(())
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionF6ErrorV2> {
        self.validate()?;
        let acceptance = self
            .acceptance
            .canonical_bytes()
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(NATIVE_COMMITMENT_MAGIC_V25);
        bytes.extend_from_slice(&25u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(DOMAIN);
        encode_wire(&mut bytes, self.wire);
        bytes.extend_from_slice(&self.acceptance_envelope);
        bytes.extend_from_slice(&self.acceptance_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.selection_inputs);
        bytes.extend_from_slice(&self.binding_evidence);
        bytes.extend_from_slice(&self.committed_state);
        bytes.extend_from_slice(&self.committed_revision.to_be_bytes());
        bytes.extend_from_slice(&self.execution_fence.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .acceptance
                .message_digest()
                .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?,
        );
        put_bytes(&mut bytes, &acceptance)?;
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ProductionF6ErrorV2> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        let mut reader = Reader { bytes, cursor: 0 };
        if reader.take(8)? != NATIVE_COMMITMENT_MAGIC_V25
            || reader.u16()? != 25
            || reader.u16()? != 0
            || reader.take(DOMAIN.len())? != DOMAIN
        {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        let wire = decode_wire(&mut reader)?;
        let acceptance_envelope = reader.array()?;
        let acceptance_sequence = reader.u64()?;
        let selection_inputs = reader.array()?;
        let binding_evidence = reader.array()?;
        let committed_state = reader.array()?;
        let committed_revision = reader.u64()?;
        let execution_fence = reader.u64()?;
        let acceptance_digest: Digest32 = reader.array()?;
        let acceptance =
            NativeAcceptanceV25::decode(reader.bounded_bytes(MAX_NATIVE_ACCEPTANCE_BYTES_V25)?)
                .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        if acceptance
            .message_digest()
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?
            != acceptance_digest
            || reader.cursor != bytes.len()
        {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        let value = Self {
            wire,
            acceptance,
            acceptance_envelope,
            acceptance_sequence,
            selection_inputs,
            binding_evidence,
            committed_state,
            committed_revision,
            execution_fence,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        Ok(value)
    }

    pub(crate) fn digest(&self) -> Result<Digest32, ProductionF6ErrorV2> {
        digest_parts(&[DOMAIN, &self.canonical_bytes()?])
    }
}

/// Called ONLY after the native acceptance handler committed its full original
/// Applied receipt. A public acceptance object alone cannot call this boundary.
pub(crate) fn retain_native_acceptance_v25(
    binding: ProductionSolverF6BindingV2,
    role: NativeAcceptanceReceiptRoleV25,
    receipts: &mut Store,
    ledger: &DurableBindingV2<StoreLogV2>,
    delivery: &F6PayloadDeliveryV1<'_>,
) -> Result<(), ProductionF6ErrorV2> {
    require_receipts(binding, role, receipts)?;
    if delivery.message_type() != relay::auth::message_type::ACCEPTANCE
        || delivery.sender_id() != binding.initiator
    {
        return Err(ProductionF6ErrorV2::WrongRole);
    }
    let acceptance = NativeAcceptanceV25::decode(delivery.payload())
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
    require_accepted_binding(binding, ledger, &acceptance)?;
    let applied_receipt = delivery_record(delivery, DurablePayloadDispositionV1::Applied)?;
    require_existing_exact(
        receipts,
        DELIVERY_NAMESPACE,
        delivery.envelope_digest(),
        &applied_receipt,
    )?;
    let retained = RetainedAcceptanceV25 {
        acceptance,
        envelope: *delivery.envelope_digest(),
        sequence: delivery.sequence(),
        applied_receipt,
    };
    let bytes = encode_accepted(binding, &retained)?;
    retain_exact(receipts, ACCEPTED_NAMESPACE, &binding.rfq_id, &bytes)
}

impl ProductionSolverF6AuthorityV2 {
    /// Read-only binding check for an already freshly recovered real inventory
    /// capability. This grants nothing and does not replace the caller's current
    /// status, time, registry or live inventory checks.
    pub(crate) fn require_native_execution_binding_v25(
        &self,
        capability: &CommittedInventoryCapabilityV2,
    ) -> Result<(), ProductionF6ErrorV2> {
        if !self.sources.terms.is_native() || self.historical_recovery_v24.is_some() {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        let accepted = load_accepted(
            self.binding,
            NativeAcceptanceReceiptRoleV25::Solver,
            &self.receipts,
            &self.binding_log,
        )?;
        let bound = self
            .binding_log
            .accepted_binding_v2(
                self.binding.composition_id,
                self.binding.position,
                self.binding.rfq_id,
            )
            .ok_or(ProductionF6ErrorV2::Binding)?;
        // Same domain, field order and length-prefix framing as the original
        // solver-inventory binding_evidence_digest_v2 / CommitmentWriter.
        // Input is the sealed durable ledger view, never caller-supplied facts.
        let expected_evidence = digest_parts(&[
            b"DOM-INTEROP/F6-ACCEPTED-BINDING-EVIDENCE/V2",
            &bound.composition_id(),
            &[bound.position() as u8],
            &bound.rfq_id(),
            &bound.quote_id(),
            &bound.solver().0,
            &bound.accepted_by().0,
            &bound.reservation_id(),
            &bound.terms_hash(),
        ])?;
        let quote = capability.quote_capability();
        if quote.composition_id() != bound.composition_id()
            || quote.position() != bound.position()
            || quote.rfq_id() != bound.rfq_id()
            || quote.quote_id() != bound.quote_id()
            || quote.solver_id() != bound.solver()
            || quote.reservation_id() != bound.reservation_id()
            || quote.route_id() != self.binding.wire.route_id
            || capability.accepted_terms_digest()
                != accepted.acceptance.inner_acceptance().terms_hash
            || capability.binding_evidence_digest() != expected_evidence
            || capability.execution_fencing_epoch() != self.shared.inventory_lease().fencing_epoch
            || capability.reservation_digest() == ZERO_DIGEST
            || capability.reservation_revision() == 0
        {
            return Err(ProductionF6ErrorV2::Inventory);
        }
        Ok(())
    }

    /// Reads the already authenticated native acceptance and issues only from
    /// current real committed inventory under the retained exclusive lease.
    /// Re-fencing or changing committed state cannot silently replace an old
    /// outbound certificate; that needs an explicit reconciliation protocol.
    pub(crate) fn prepare_native_commitment_v25(
        &mut self,
    ) -> Result<PreparedNativeCommitmentV25, ProductionF6ErrorV2> {
        if !self.sources.terms.is_native() || self.historical_recovery_v24.is_some() {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        let accepted = load_accepted(
            self.binding,
            NativeAcceptanceReceiptRoleV25::Solver,
            &self.receipts,
            &self.binding_log,
        )?;
        let wall = observe_trusted_wall()?;
        let quote = self.load_local_quote(wall.milliseconds)?;
        let rfq = self.load_rfq()?;
        let committed = self
            .shared
            .inventory_mut()?
            .committed_capability_v2(
                self.shared.inventory_lease(),
                quote.bond_reservation_id,
                wall.milliseconds,
            )
            .map_err(map_inventory)?;
        validate_capability(self.binding, &rfq, &quote, committed.quote_capability())?;
        self.require_native_execution_binding_v25(&committed)?;
        // The ORIGINAL V25 acceptance already commits full native terms and
        // prepared-record identity. It was validated by the native acceptance
        // owner before its Applied receipt. Never reinterpret a public proposal
        // as consent or require/create a legacy TERMS_NAMESPACE authority.
        if committed.accepted_terms_digest() != accepted.acceptance.inner_acceptance().terms_hash
            || committed.execution_fencing_epoch() != self.shared.inventory_lease().fencing_epoch
            || committed.binding_evidence_digest() == ZERO_DIGEST
            || committed.reservation_digest() == ZERO_DIGEST
            || committed.reservation_revision() == 0
        {
            return Err(ProductionF6ErrorV2::Inventory);
        }
        let selected =
            require_accepted_binding(self.binding, &self.binding_log, &accepted.acceptance)?;
        let certificate = NativeCommitmentCertificateV25 {
            wire: self.binding.wire,
            acceptance: accepted.acceptance,
            acceptance_envelope: accepted.envelope,
            acceptance_sequence: accepted.sequence,
            selection_inputs: selected,
            binding_evidence: committed.binding_evidence_digest(),
            committed_state: committed.reservation_digest(),
            committed_revision: committed.reservation_revision(),
            execution_fence: committed.execution_fencing_epoch(),
        };
        let bytes = certificate.canonical_bytes()?;
        retain_exact(
            &mut self.receipts,
            OUTBOUND_NAMESPACE,
            &self.binding.rfq_id,
            &bytes,
        )?;
        Ok(PreparedNativeCommitmentV25 { certificate })
    }
}

/// Verify the solver's ORIGINAL authenticated envelope against the initiator's
/// original accepted delivery and selection. This does not mint local solver
/// inventory authority and does not interpret an ACK or Ready vote as consent.
pub(crate) fn verify_native_commitment_v25(
    binding: ProductionSolverF6BindingV2,
    receipts: &Store,
    ledger: &DurableBindingV2<StoreLogV2>,
    delivery: &F6PayloadDeliveryV1<'_>,
) -> Result<VerifiedNativeCommitmentV25, ProductionF6ErrorV2> {
    if delivery.message_type() != NATIVE_COMMITMENT_MESSAGE_TYPE_V25
        || delivery.sender_id() != binding.solver
    {
        return Err(ProductionF6ErrorV2::WrongRole);
    }
    let accepted = load_accepted(
        binding,
        NativeAcceptanceReceiptRoleV25::Initiator,
        receipts,
        ledger,
    )?;
    let certificate = NativeCommitmentCertificateV25::decode(delivery.payload())?;
    let selected = require_accepted_binding(binding, ledger, &accepted.acceptance)?;
    require_certificate_acceptance(binding, &accepted, selected, &certificate)?;
    Ok(VerifiedNativeCommitmentV25 {
        certificate,
        solver_envelope: *delivery.envelope_digest(),
        solver_sequence: delivery.sequence(),
    })
}

/// Persist only a verified original remote statement. Caller then persists its
/// ordinary Applied receipt; an exact crash retry re-verifies the same envelope.
pub(crate) fn retain_verified_native_commitment_v25(
    binding: ProductionSolverF6BindingV2,
    receipts: &mut Store,
    verified: &VerifiedNativeCommitmentV25,
) -> Result<(), ProductionF6ErrorV2> {
    require_receipts(binding, NativeAcceptanceReceiptRoleV25::Initiator, receipts)?;
    if verified.certificate.wire != binding.wire
        || verified.certificate.acceptance.rfq_id() != binding.rfq_id
    {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    let mut bytes = verified.certificate.canonical_bytes()?;
    bytes.extend_from_slice(&verified.solver_envelope);
    bytes.extend_from_slice(&verified.solver_sequence.to_be_bytes());
    retain_exact(receipts, REMOTE_NAMESPACE, &binding.rfq_id, &bytes)
}

/// Read-only exact replay. A write-before-Applied crash prefix remains
/// unavailable until the original authenticated delivery finishes normally.
pub(crate) fn reopen_native_commitment_v25(
    binding: ProductionSolverF6BindingV2,
    receipts: &Store,
    ledger: &DurableBindingV2<StoreLogV2>,
) -> Result<RetainedNativeCommitmentV25, ProductionF6ErrorV2> {
    let accepted = load_accepted(
        binding,
        NativeAcceptanceReceiptRoleV25::Initiator,
        receipts,
        ledger,
    )?;
    let bytes = receipts
        .opaque(REMOTE_NAMESPACE, &binding.rfq_id)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?
        .ok_or(ProductionF6ErrorV2::Receipt)?;
    if bytes.len() > MAX_CERTIFICATE_BYTES + 40 {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    let split = bytes
        .len()
        .checked_sub(40)
        .ok_or(ProductionF6ErrorV2::Receipt)?;
    let certificate = NativeCommitmentCertificateV25::decode(&bytes[..split])?;
    let mut reader = Reader {
        bytes: &bytes[split..],
        cursor: 0,
    };
    let solver_envelope = reader.array()?;
    let solver_sequence = reader.u64()?;
    if solver_envelope == ZERO_DIGEST {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    let selected = require_accepted_binding(binding, ledger, &accepted.acceptance)?;
    require_certificate_acceptance(binding, &accepted, selected, &certificate)?;
    let applied = expected_applied_receipt(
        binding.solver,
        solver_sequence,
        solver_envelope,
        NATIVE_COMMITMENT_MESSAGE_TYPE_V25,
        &certificate.canonical_bytes()?,
    )?;
    require_existing_exact(receipts, DELIVERY_NAMESPACE, &solver_envelope, &applied)?;
    Ok(RetainedNativeCommitmentV25 {
        verified: VerifiedNativeCommitmentV25 {
            certificate,
            solver_envelope,
            solver_sequence,
        },
    })
}

fn require_certificate_acceptance(
    binding: ProductionSolverF6BindingV2,
    accepted: &RetainedAcceptanceV25,
    selected: Digest32,
    certificate: &NativeCommitmentCertificateV25,
) -> Result<(), ProductionF6ErrorV2> {
    certificate.validate()?;
    if certificate.wire != binding.wire
        || certificate.acceptance != accepted.acceptance
        || certificate.acceptance_envelope != accepted.envelope
        || certificate.acceptance_sequence != accepted.sequence
        || certificate.selection_inputs != selected
    {
        return Err(ProductionF6ErrorV2::InvalidPayload);
    }
    Ok(())
}

fn require_accepted_binding(
    binding: ProductionSolverF6BindingV2,
    ledger: &DurableBindingV2<StoreLogV2>,
    acceptance: &NativeAcceptanceV25,
) -> Result<Digest32, ProductionF6ErrorV2> {
    binding.validate()?;
    let inner = acceptance.inner_acceptance();
    let terms = acceptance.terms();
    let bound = ledger
        .ledger()
        .binding(binding.composition_id, binding.position, binding.rfq_id)
        .ok_or(ProductionF6ErrorV2::Binding)?;
    let selected = ledger
        .ledger()
        .selection(binding.composition_id, binding.position, binding.rfq_id)
        .ok_or(ProductionF6ErrorV2::Binding)?;
    if acceptance.accepted_by() != binding.initiator
        || acceptance.session_id() != binding.wire.session_id
        || acceptance.composition_id() != binding.composition_id
        || acceptance.position() != binding.position
        || acceptance.rfq_id() != binding.rfq_id
        || terms.solver_id != binding.solver
        || bound.quote_id != acceptance.quote_id()
        || bound.solver != binding.solver
        || bound.accepted_by != binding.initiator
        || bound.reservation_id != terms.bond_reservation_id
        || bound.terms_hash != inner.terms_hash
        || selected.winning_quote != acceptance.quote_id()
        || selected.inputs_digest == ZERO_DIGEST
    {
        return Err(ProductionF6ErrorV2::Binding);
    }
    Ok(selected.inputs_digest)
}

fn require_receipts(
    binding: ProductionSolverF6BindingV2,
    role: NativeAcceptanceReceiptRoleV25,
    receipts: &Store,
) -> Result<(), ProductionF6ErrorV2> {
    let domain = match role {
        NativeAcceptanceReceiptRoleV25::Initiator => NATIVE_INITIATOR_RECEIPTS_DOMAIN_V25,
        NativeAcceptanceReceiptRoleV25::Solver => NATIVE_SOLVER_RECEIPTS_DOMAIN_V25,
    };
    let expected = ProductionStoreBindingV1::new(binding.authority_digest(domain)?)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?;
    receipts
        .require_production_binding(expected)
        .map_err(|_| ProductionF6ErrorV2::Receipt)
}

fn load_accepted(
    binding: ProductionSolverF6BindingV2,
    role: NativeAcceptanceReceiptRoleV25,
    receipts: &Store,
    ledger: &DurableBindingV2<StoreLogV2>,
) -> Result<RetainedAcceptanceV25, ProductionF6ErrorV2> {
    require_receipts(binding, role, receipts)?;
    let bytes = receipts
        .opaque(ACCEPTED_NAMESPACE, &binding.rfq_id)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?
        .ok_or(ProductionF6ErrorV2::Receipt)?;
    let accepted = decode_accepted(binding, &bytes)?;
    require_existing_exact(
        receipts,
        DELIVERY_NAMESPACE,
        &accepted.envelope,
        &accepted.applied_receipt,
    )?;
    require_accepted_binding(binding, ledger, &accepted.acceptance)?;
    Ok(accepted)
}

fn encode_accepted(
    binding: ProductionSolverF6BindingV2,
    accepted: &RetainedAcceptanceV25,
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    if accepted.envelope == ZERO_DIGEST
        || accepted.applied_receipt
            != expected_applied_receipt(
                binding.initiator,
                accepted.sequence,
                accepted.envelope,
                relay::auth::message_type::ACCEPTANCE,
                &accepted
                    .acceptance
                    .canonical_bytes()
                    .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?,
            )?
    {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    let mut bytes = Vec::with_capacity(2048);
    bytes.extend_from_slice(ACCEPTED_DOMAIN);
    bytes.extend_from_slice(&binding.authority_digest(ACCEPTED_DOMAIN)?);
    bytes.extend_from_slice(&accepted.envelope);
    bytes.extend_from_slice(&accepted.sequence.to_be_bytes());
    put_bytes(
        &mut bytes,
        &accepted
            .acceptance
            .canonical_bytes()
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?,
    )?;
    put_bytes(&mut bytes, &accepted.applied_receipt)?;
    let digest = digest_parts(&[ACCEPTED_DOMAIN, &bytes])?;
    bytes.extend_from_slice(&digest);
    if bytes.len() > MAX_ACCEPTED_RECORD_BYTES {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    Ok(bytes)
}

fn decode_accepted(
    binding: ProductionSolverF6BindingV2,
    bytes: &[u8],
) -> Result<RetainedAcceptanceV25, ProductionF6ErrorV2> {
    if bytes.len() > MAX_ACCEPTED_RECORD_BYTES {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    let mut reader = Reader { bytes, cursor: 0 };
    if reader.take(ACCEPTED_DOMAIN.len())? != ACCEPTED_DOMAIN
        || reader.array::<32>()? != binding.authority_digest(ACCEPTED_DOMAIN)?
    {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    let envelope = reader.array()?;
    let sequence = reader.u64()?;
    let acceptance =
        NativeAcceptanceV25::decode(reader.bounded_bytes(MAX_NATIVE_ACCEPTANCE_BYTES_V25)?)
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
    let applied_receipt = reader.bounded_bytes(512)?.to_vec();
    let _digest: Digest32 = reader.array()?;
    if reader.cursor != bytes.len() {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    let retained = RetainedAcceptanceV25 {
        acceptance,
        envelope,
        sequence,
        applied_receipt,
    };
    if encode_accepted(binding, &retained)?.as_slice() != bytes {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    Ok(retained)
}

// Reconstruct only PUBLIC expected receipt bytes for comparison against the
// existing durable receipt. This neither creates a delivery nor writes consent.
fn expected_applied_receipt(
    sender: ParticipantId,
    sequence: u64,
    envelope: Digest32,
    kind: u16,
    payload: &[u8],
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    if !matches!(
        kind,
        relay::auth::message_type::ACCEPTANCE | NATIVE_COMMITMENT_MESSAGE_TYPE_V25
    ) {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    let mut record = Vec::with_capacity(256);
    record.extend_from_slice(RECEIPT_DOMAIN);
    record.extend_from_slice(&sender.0);
    record.extend_from_slice(&sequence.to_be_bytes());
    record.extend_from_slice(&kind.to_be_bytes());
    record.extend_from_slice(&envelope);
    record.extend_from_slice(&digest_parts(&[payload])?);
    record.push(1); // Existing durable Applied encoding, never an issued grant.
    let digest = digest_parts(&[&record])?;
    record.extend_from_slice(&digest);
    Ok(record)
}

fn require_existing_exact(
    receipts: &Store,
    namespace: &[u8],
    key: &[u8],
    bytes: &[u8],
) -> Result<(), ProductionF6ErrorV2> {
    if receipts
        .opaque(namespace, key)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?
        .as_deref()
        != Some(bytes)
    {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    Ok(())
}
fn retain_exact(
    receipts: &mut Store,
    namespace: &[u8],
    key: &[u8],
    bytes: &[u8],
) -> Result<(), ProductionF6ErrorV2> {
    receipts
        .put_opaque_if_absent(namespace, key, bytes)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?;
    require_existing_exact(receipts, namespace, key, bytes)
}
fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ProductionF6ErrorV2> {
    output.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}
fn encode_wire(bytes: &mut Vec<u8>, wire: RouteWireContextV1) {
    bytes.extend_from_slice(&wire.network_id);
    bytes.extend_from_slice(&wire.route_id);
    bytes.extend_from_slice(&wire.session_id);
    bytes.extend_from_slice(&wire.roster_snapshot);
    bytes.extend_from_slice(&wire.policy_version.to_be_bytes());
}
fn decode_wire(reader: &mut Reader<'_>) -> Result<RouteWireContextV1, ProductionF6ErrorV2> {
    Ok(RouteWireContextV1 {
        network_id: reader.array()?,
        route_id: reader.array()?,
        session_id: reader.array()?,
        roster_snapshot: reader.array()?,
        policy_version: reader.u32()?,
    })
}
struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], ProductionF6ErrorV2> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(ProductionF6ErrorV2::InvalidPayload)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ProductionF6ErrorV2::InvalidPayload)?;
        self.cursor = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProductionF6ErrorV2> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)
    }
    fn u16(&mut self) -> Result<u16, ProductionF6ErrorV2> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, ProductionF6ErrorV2> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, ProductionF6ErrorV2> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn bounded_bytes(&mut self, max: usize) -> Result<&'a [u8], ProductionF6ErrorV2> {
        let len = usize::try_from(self.u32()?).map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        if len == 0 || len > max {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        self.take(len)
    }
}

#[cfg(test)]
#[path = "native_commitment_v25_tests.rs"]
mod tests;
