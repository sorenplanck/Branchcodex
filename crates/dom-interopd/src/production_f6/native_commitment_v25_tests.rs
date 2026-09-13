//! Public encoding/refusal regressions. No real committed inventory, signed
//! Relay delivery or remote economic-ready capability is fabricated here.

use super::*;
use rfq::v2::{
    NativeClockKindV2, NegotiationInstantV2, QuoteProposalV2, RfqRequestV2, RouteV2,
    ScopedTimelockV2,
};
use rfq::{AssetId, FeeLimitV1, LegDirectionV1, PolicyId, RfqModeV1, RouteLegV1};
use std::fs;
use std::os::unix::fs::PermissionsExt;

static_assertions::assert_not_impl_any!(PreparedNativeCommitmentV25: Clone, Copy);
static_assertions::assert_not_impl_any!(VerifiedNativeCommitmentV25: Clone, Copy);
static_assertions::assert_not_impl_any!(RetainedNativeCommitmentV25: Clone, Copy);

fn fixture() -> (
    ProductionSolverF6BindingV2,
    NativeCommitmentCertificateV25,
    RetainedAcceptanceV25,
) {
    let dom = ChainId([0x10; 32]);
    let xmr = ChainId([0x20; 32]);
    let route = RouteV2 {
        composition_id: [0x30; 32],
        position: SettlementPositionV2::Upstream,
        legs: [
            RouteLegV1 {
                chain_id: dom,
                asset: AssetId([0x40; 32]),
                direction: LegDirectionV1::UserReceives,
            },
            RouteLegV1 {
                chain_id: xmr,
                asset: AssetId([0x50; 32]),
                direction: LegDirectionV1::UserGives,
            },
        ],
    };
    let clock = NegotiationClockV2 {
        chain_id: dom,
        profile_digest: [0x60; 32],
        authority_scope: [0x61; 32],
        kind: NativeClockKindV2::BlockHeight,
    };
    let instant = |value| NegotiationInstantV2 { clock, value };
    let rfq = RfqV2::create(RfqRequestV2 {
        initiator: ParticipantId([1; 32]),
        route,
        mode: RfqModeV1::ExactIn {
            input_amount: 100,
            minimum_output: 90,
        },
        fee_limit: FeeLimitV1 {
            dom_max: 4,
            counterparty_max: 6,
        },
        negotiation_clock: clock,
        quote_deadline: instant(1100),
        assurance_policy_ref: PolicyId([0x62; 32]),
        policy_version: 3,
        session_id: [0x63; 32],
    })
    .unwrap();
    let quote = QuoteV2::create(QuoteProposalV2 {
        rfq_id: rfq.rfq_id,
        solver: ParticipantId([2; 32]),
        route,
        net_output: 95,
        total_input: 100,
        total_fee: 7,
        execution_deadline: instant(1080),
        bond_reservation_id: [0x64; 32],
        bond_policy_version: 3,
        expiry: instant(1050),
        solver_signature: [0; 64],
    })
    .unwrap(); // Unsigned DATA fixture only.
    let faces = route.legs.map(|leg| RefundFaceV2 {
        direction: leg.direction,
        chain_id: leg.chain_id,
        refund_deadline: ScopedTimelockV2 {
            chain_id: leg.chain_id,
            kind: NativeClockKindV2::BlockHeight,
            value: if leg.chain_id == dom { 2000 } else { 3000 },
        },
        payout_commitment: [0x65; 32],
    });
    let terms = TermsBindingV2::from_parts(&rfq, &quote, faces).unwrap();
    let acceptance = NativeAcceptanceV25::new(&terms, [0x66; 32], rfq.initiator).unwrap();
    let wire = RouteWireContextV1 {
        network_id: [0x67; 32],
        route_id: [0x68; 32],
        session_id: rfq.session_id,
        roster_snapshot: [0x69; 32],
        policy_version: 3,
    };
    let pins = ProductionF6PinsV2 {
        inventory_binding_digest: [0x70; 32],
        registry_digest: [0x71; 32],
        registry_epoch: 1,
        profile_bundle_digest: [0x72; 32],
        bond_policy_hash: [0x73; 32],
        bond_asset_binding_digest: [0x74; 32],
        required_collateral: 1,
        bond_attestation_authority_set_digest: [0x75; 32],
        remote_status_authority_set_digest: [0x76; 32],
        solver_status_scope_digest: [0x77; 32],
        pre_f6_time_scope_digest: [0x78; 32],
    };
    let binding = ProductionSolverF6BindingV2::new(wire, &rfq, quote.solver, dom, pins).unwrap();
    let certificate = NativeCommitmentCertificateV25 {
        wire,
        acceptance,
        acceptance_envelope: [0x79; 32],
        acceptance_sequence: 7,
        selection_inputs: [0x80; 32],
        binding_evidence: [0x81; 32],
        committed_state: [0x82; 32],
        committed_revision: 8,
        execution_fence: 9,
    };
    let accepted = RetainedAcceptanceV25 {
        acceptance,
        envelope: certificate.acceptance_envelope,
        sequence: certificate.acceptance_sequence,
        applied_receipt: expected_applied_receipt(
            binding.initiator,
            certificate.acceptance_sequence,
            certificate.acceptance_envelope,
            relay::auth::message_type::ACCEPTANCE,
            &acceptance.canonical_bytes().unwrap(),
        )
        .unwrap(),
    };
    (binding, certificate, accepted)
}

#[test]
fn native_commitment_public_codec_roundtrip_commits_complete_outer_acceptance_v25() {
    let (_, certificate, _) = fixture();
    let bytes = certificate.canonical_bytes().unwrap();
    let decoded = NativeCommitmentCertificateV25::decode(&bytes).unwrap();
    assert_eq!(decoded, certificate);
    assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    assert_eq!(decoded.digest().unwrap(), certificate.digest().unwrap());
    assert_eq!(
        decoded.acceptance.canonical_bytes().unwrap(),
        certificate.acceptance.canonical_bytes().unwrap()
    );
    assert!(bytes.len() <= MAX_CERTIFICATE_BYTES);
    // Public decoder success is deliberately not a Verified/Retained owner.
}

#[test]
fn native_commitment_never_decodes_legacy_acceptance_ready_or_ack_v25() {
    let (_, certificate, _) = fixture();
    for bytes in [
        certificate.acceptance.canonical_bytes().unwrap(),
        certificate
            .acceptance
            .inner_acceptance()
            .canonical_bytes()
            .unwrap(),
        vec![0x17; 160],
        b"ACK".to_vec(),
    ] {
        assert!(NativeCommitmentCertificateV25::decode(&bytes).is_err());
    }
    let bytes = certificate.canonical_bytes().unwrap();
    assert!(NativeAcceptanceV25::decode(&bytes).is_err());
    assert!(AcceptanceV2::decode(&bytes).is_err());
}

#[test]
fn native_commitment_header_bounds_truncations_suffixes_and_every_byte_are_closed_v25() {
    let (_, certificate, _) = fixture();
    let bytes = certificate.canonical_bytes().unwrap();
    for end in 0..bytes.len() {
        assert!(NativeCommitmentCertificateV25::decode(&bytes[..end]).is_err());
    }
    let mut suffix = bytes.clone();
    suffix.push(0);
    assert!(NativeCommitmentCertificateV25::decode(&suffix).is_err());
    assert!(NativeCommitmentCertificateV25::decode(&vec![0; MAX_CERTIFICATE_BYTES + 1]).is_err());
    for index in 0..12 + DOMAIN.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(NativeCommitmentCertificateV25::decode(&changed).is_err());
    }
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        if let Ok(decoded) = NativeCommitmentCertificateV25::decode(&changed) {
            assert_ne!(decoded, certificate);
            assert_ne!(decoded.digest().unwrap(), certificate.digest().unwrap());
        }
    }
}

#[test]
fn native_commitment_zero_commit_revision_fence_or_scope_is_not_a_certificate_v25() {
    let (_, certificate, _) = fixture();
    for operand in 0..11 {
        let mut changed = certificate.clone();
        match operand {
            0 => changed.wire.network_id = ZERO_DIGEST,
            1 => changed.wire.route_id = ZERO_DIGEST,
            2 => changed.wire.session_id = ZERO_DIGEST,
            3 => changed.wire.roster_snapshot = ZERO_DIGEST,
            4 => changed.wire.policy_version = 0,
            5 => changed.acceptance_envelope = ZERO_DIGEST,
            6 => changed.selection_inputs = ZERO_DIGEST,
            7 => changed.binding_evidence = ZERO_DIGEST,
            8 => changed.committed_state = ZERO_DIGEST,
            9 => changed.committed_revision = 0,
            10 => changed.execution_fence = 0,
            _ => unreachable!(),
        }
        assert!(changed.canonical_bytes().is_err());
    }
}

#[test]
fn native_commitment_matches_original_envelope_record_snapshot_and_all_wire_fields_v25() {
    let (binding, certificate, accepted) = fixture();
    assert!(require_certificate_acceptance(
        binding,
        &accepted,
        certificate.selection_inputs,
        &certificate
    )
    .is_ok());
    for operand in 0..10 {
        let mut changed = certificate.clone();
        match operand {
            0 => changed.wire.network_id[0] ^= 1,
            1 => changed.wire.route_id[0] ^= 1,
            2 => changed.wire.session_id[0] ^= 1,
            3 => changed.wire.roster_snapshot[0] ^= 1,
            4 => changed.wire.policy_version += 1,
            5 => changed.acceptance_envelope[0] ^= 1,
            6 => changed.acceptance_sequence += 1,
            7 => changed.selection_inputs[0] ^= 1,
            8 => {
                changed.acceptance = NativeAcceptanceV25::new(
                    certificate.acceptance.terms(),
                    [0x90; 32],
                    binding.initiator,
                )
                .unwrap()
            }
            9 => {
                let mut terms = *certificate.acceptance.terms();
                terms.total_fee += 1;
                changed.acceptance = NativeAcceptanceV25::new(
                    &terms,
                    certificate.acceptance.prepared_record_digest(),
                    binding.initiator,
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(require_certificate_acceptance(
            binding,
            &accepted,
            certificate.selection_inputs,
            &changed
        )
        .is_err());
    }
}

#[test]
fn retained_native_acceptance_record_rejects_changed_payload_sequence_or_receipt_v25() {
    let (binding, _, accepted) = fixture();
    let original = encode_accepted(binding, &accepted).unwrap();
    let decoded = decode_accepted(binding, &original).unwrap();
    assert_eq!(encode_accepted(binding, &decoded).unwrap(), original);
    for index in 0..original.len() {
        let mut changed = original.clone();
        changed[index] ^= 1;
        assert!(decode_accepted(binding, &changed).is_err());
    }
    let mut different = binding;
    different.wire.route_id[0] ^= 1;
    assert!(decode_accepted(different, &original).is_err());
    let mut changed = accepted;
    changed.sequence += 1;
    assert!(encode_accepted(binding, &changed).is_err());
    changed.sequence -= 1;
    changed.applied_receipt = b"transport ACK".to_vec();
    assert!(encode_accepted(binding, &changed).is_err());
}

#[test]
fn native_commitment_receipts_are_role_scoped_immutable_and_missing_applied_refuses_v25(
) -> Result<(), Box<dyn std::error::Error>> {
    let (binding, _, accepted) = fixture();
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let receipt_path = directory.path().join("initiator.sqlite3");
    let physical = ProductionStoreBindingV1::new(
        binding.authority_digest(NATIVE_INITIATOR_RECEIPTS_DOMAIN_V25)?,
    )?;
    let mut receipts = Store::create_production(&receipt_path, physical)?;
    assert!(require_receipts(
        binding,
        NativeAcceptanceReceiptRoleV25::Initiator,
        &receipts
    )
    .is_ok());
    assert!(require_receipts(binding, NativeAcceptanceReceiptRoleV25::Solver, &receipts).is_err());
    let bytes = encode_accepted(binding, &accepted)?;
    retain_exact(&mut receipts, ACCEPTED_NAMESPACE, &binding.rfq_id, &bytes)?;
    assert!(retain_exact(
        &mut receipts,
        ACCEPTED_NAMESPACE,
        &binding.rfq_id,
        b"different original"
    )
    .is_err());
    let log =
        StoreLogV2::create_production(&directory.path().join("empty-ledger.sqlite3"), [0x91; 32])?;
    let ledger = DurableBindingV2::open(log)?;
    // A public accepted-record blob, even canonical, has no original Applied
    // delivery or bound ledger. No remote authority can be obtained from it.
    assert!(load_accepted(
        binding,
        NativeAcceptanceReceiptRoleV25::Initiator,
        &receipts,
        &ledger
    )
    .is_err());
    assert!(reopen_native_commitment_v25(binding, &receipts, &ledger).is_err());
    receipts.put_opaque(DELIVERY_NAMESPACE, &accepted.envelope, b"ACK")?;
    assert!(load_accepted(
        binding,
        NativeAcceptanceReceiptRoleV25::Initiator,
        &receipts,
        &ledger
    )
    .is_err());
    drop(receipts);
    let receipts = Store::open_production(&receipt_path, physical)?;
    assert_eq!(
        receipts
            .opaque(ACCEPTED_NAMESPACE, &binding.rfq_id)?
            .as_deref(),
        Some(bytes.as_slice())
    );
    assert!(reopen_native_commitment_v25(binding, &receipts, &ledger).is_err());
    Ok(())
}

#[test]
fn native_commitment_physical_store_reopen_rejects_legacy_downgrade_and_other_role_v25(
) -> Result<(), Box<dyn std::error::Error>> {
    use super::super::native_acceptance_v25::{
        NATIVE_INITIATOR_LOG_DOMAIN_V25, NATIVE_SOLVER_LOG_DOMAIN_V25,
    };
    let (binding, _, _) = fixture();
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let receipt_domains: [&[u8]; 4] = [
        NATIVE_SOLVER_RECEIPTS_DOMAIN_V25,
        NATIVE_INITIATOR_RECEIPTS_DOMAIN_V25,
        RECEIPT_BINDING_DOMAIN,
        b"DOM-INTEROP/INTEROPD/F6-INITIATOR-RECEIPTS/V25\0",
    ];
    for (index, domain) in receipt_domains.iter().enumerate() {
        let path = directory.path().join(format!("receipts-{index}.sqlite3"));
        let physical = ProductionStoreBindingV1::new(binding.authority_digest(domain)?)?;
        let mut store = Store::create_production(&path, physical)?;
        store.put_opaque(b"test-identity", b"key", b"exact original bytes")?;
        drop(store);
        for (other_index, other_domain) in receipt_domains.iter().enumerate() {
            if other_index != index {
                let other = ProductionStoreBindingV1::new(binding.authority_digest(other_domain)?)?;
                assert!(Store::open_production(&path, other).is_err());
            }
        }
        let store = Store::open_production(&path, physical)?;
        assert_eq!(
            store.opaque(b"test-identity", b"key")?.as_deref(),
            Some(b"exact original bytes".as_slice())
        );
    }
    let log_domains: [&[u8]; 4] = [
        NATIVE_SOLVER_LOG_DOMAIN_V25,
        NATIVE_INITIATOR_LOG_DOMAIN_V25,
        LOG_BINDING_DOMAIN,
        b"DOM-INTEROP/INTEROPD/F6-INITIATOR-LOG/V25\0",
    ];
    for (index, domain) in log_domains.iter().enumerate() {
        let path = directory.path().join(format!("ledger-{index}.sqlite3"));
        let physical = binding.authority_digest(domain)?;
        drop(StoreLogV2::create_production(&path, physical)?);
        for (other_index, other_domain) in log_domains.iter().enumerate() {
            if other_index != index {
                assert!(StoreLogV2::open_production(
                    &path,
                    binding.authority_digest(other_domain)?
                )
                .is_err());
            }
        }
        drop(StoreLogV2::open_production(&path, physical)?);
    }
    Ok(())
}

#[test]
fn native_commitment_producer_requires_real_solver_owner_not_caller_commit_fields_v25() {
    let _producer: fn(
        &mut ProductionSolverF6AuthorityV2,
    ) -> Result<PreparedNativeCommitmentV25, ProductionF6ErrorV2> =
        ProductionSolverF6AuthorityV2::prepare_native_commitment_v25;
    let _execution_binding: fn(
        &ProductionSolverF6AuthorityV2,
        &CommittedInventoryCapabilityV2,
    ) -> Result<(), ProductionF6ErrorV2> =
        ProductionSolverF6AuthorityV2::require_native_execution_binding_v25;
    // No constructor takes a caller-authored revision, fence, inventory digest,
    // unsigned acceptance or raw boolean to issue Prepared/Verified owners.
}

#[test]
fn native_commitment_sequence_zero_is_valid_but_exactly_bound_v25() {
    let (binding, mut certificate, mut accepted) = fixture();
    certificate.acceptance_sequence = 0;
    accepted.sequence = 0;
    accepted.applied_receipt = expected_applied_receipt(
        binding.initiator,
        0,
        accepted.envelope,
        relay::auth::message_type::ACCEPTANCE,
        &accepted.acceptance.canonical_bytes().unwrap(),
    )
    .unwrap();
    let encoded = certificate.canonical_bytes().unwrap();
    assert_eq!(
        NativeCommitmentCertificateV25::decode(&encoded).unwrap(),
        certificate
    );
    let retained = decode_accepted(binding, &encode_accepted(binding, &accepted).unwrap()).unwrap();
    assert_eq!(retained.sequence, 0);
    assert!(require_certificate_acceptance(
        binding,
        &retained,
        certificate.selection_inputs,
        &certificate
    )
    .is_ok());
    certificate.acceptance_sequence = 1;
    assert!(require_certificate_acceptance(
        binding,
        &retained,
        certificate.selection_inputs,
        &certificate
    )
    .is_err());
    let payload = certificate.canonical_bytes().unwrap();
    assert_ne!(
        expected_applied_receipt(
            binding.solver,
            0,
            [0x92; 32],
            NATIVE_COMMITMENT_MESSAGE_TYPE_V25,
            &payload
        )
        .unwrap(),
        expected_applied_receipt(
            binding.solver,
            1,
            [0x92; 32],
            NATIVE_COMMITMENT_MESSAGE_TYPE_V25,
            &payload
        )
        .unwrap()
    );
}

#[test]
fn native_commitment_uses_only_existing_solver_quote_role_and_receipt_kind_v25() {
    let policy = relay::auth::CanonicalMessageTypePolicyV1;
    assert!(policy.permits(SenderRoleV1::Solver, NATIVE_COMMITMENT_MESSAGE_TYPE_V25));
    assert_eq!(
        NATIVE_COMMITMENT_MESSAGE_TYPE_V25,
        relay::auth::message_type::QUOTE
    );
    assert!(!policy.permits(SenderRoleV1::Solver, relay::auth::message_type::ACCEPTANCE));
    let (binding, certificate, _) = fixture();
    let payload = certificate.canonical_bytes().unwrap();
    let quote_receipt = expected_applied_receipt(
        binding.solver,
        9,
        [0x92; 32],
        NATIVE_COMMITMENT_MESSAGE_TYPE_V25,
        &payload,
    )
    .unwrap();
    let wrong_kind_receipt = expected_applied_receipt(
        binding.solver,
        9,
        [0x92; 32],
        relay::auth::message_type::ACCEPTANCE,
        &payload,
    )
    .unwrap();
    assert_ne!(quote_receipt, wrong_kind_receipt);
    assert!(expected_applied_receipt(
        binding.solver,
        9,
        [0x92; 32],
        relay::auth::message_type::ROUTE_TRANSPORT,
        &payload
    )
    .is_err());
}
