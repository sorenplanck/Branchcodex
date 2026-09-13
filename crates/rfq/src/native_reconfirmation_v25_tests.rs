//! Public codec regressions; no signatures, inventory or consent are fabricated.
use super::*;
use crate::{
    v2::{
        NativeClockKindV2, NegotiationClockV2, NegotiationInstantV2, QuoteProposalV2, QuoteV2,
        RefundFaceV2, RfqRequestV2, RfqV2, ScopedTimelockV2,
    },
    AssetId, ChainId, FeeLimitV1, LegDirectionV1, PolicyId, RfqModeV1, RouteLegV1,
};

const RECORD: Digest32 = [0x91; 32];

fn fixture(position: SettlementPositionV2) -> (RfqV2, QuoteV2, TermsBindingV2) {
    let dom = ChainId([0x10; 32]);
    let xmr = ChainId([0x20; 32]);
    let (dom_direction, xmr_direction) = match position {
        SettlementPositionV2::Upstream => (LegDirectionV1::UserReceives, LegDirectionV1::UserGives),
        SettlementPositionV2::Downstream => {
            (LegDirectionV1::UserGives, LegDirectionV1::UserReceives)
        }
    };
    let route = RouteV2 {
        composition_id: [0x30; 32],
        position,
        legs: [
            RouteLegV1 {
                chain_id: dom,
                asset: AssetId([0x40; 32]),
                direction: dom_direction,
            },
            RouteLegV1 {
                chain_id: xmr,
                asset: AssetId([0x50; 32]),
                direction: xmr_direction,
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
        solver_signature: [0; 64], // Data only: no false claim of authenticated quote.
    })
    .unwrap();
    let faces = route.legs.map(|leg| RefundFaceV2 {
        direction: leg.direction,
        chain_id: leg.chain_id,
        refund_deadline: ScopedTimelockV2 {
            chain_id: leg.chain_id,
            kind: NativeClockKindV2::BlockHeight,
            value: if leg.chain_id == dom { 2000 } else { 3000 },
        },
        payout_commitment: if leg.chain_id == dom {
            [0x65; 32]
        } else {
            [0x66; 32]
        },
    });
    let terms = TermsBindingV2::from_parts(&rfq, &quote, faces).unwrap();
    (rfq, quote, terms)
}

fn message() -> (NativeAcceptanceV25, ParticipantId) {
    let (rfq, _quote, terms) = fixture(SettlementPositionV2::Upstream);
    (
        NativeAcceptanceV25::new(&terms, RECORD, rfq.initiator).unwrap(),
        rfq.initiator,
    )
}

#[test]
fn genuine_rfq_quote_terms_roundtrip_preserves_complete_original_terms() {
    for position in [
        SettlementPositionV2::Upstream,
        SettlementPositionV2::Downstream,
    ] {
        let (rfq, quote, terms) = fixture(position);
        let original = terms.canonical_bytes().unwrap();
        let message = NativeAcceptanceV25::new(&terms, RECORD, rfq.initiator).unwrap();
        let bytes = message.canonical_bytes().unwrap();
        let decoded = NativeAcceptanceV25::decode(&bytes).unwrap();
        assert_eq!(message, decoded);
        decoded
            .validate_against(&terms, RECORD, rfq.initiator)
            .unwrap();
        assert_eq!(decoded.terms().canonical_bytes().unwrap(), original);
        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
        assert_eq!(
            decoded.message_digest().unwrap(),
            message.message_digest().unwrap()
        );
        assert_eq!(decoded.route(), rfq.route);
        assert_eq!(decoded.position(), position);
        assert_eq!(decoded.session_id(), rfq.session_id);
        assert_eq!(decoded.rfq_id(), rfq.rfq_id);
        assert_eq!(decoded.quote_id(), quote.quote_id);
        assert_eq!(decoded.composition_id(), rfq.route.composition_id);
        assert_eq!(decoded.accepted_by(), rfq.initiator);
        assert_eq!(decoded.prepared_record_digest(), RECORD);
        assert_eq!(
            decoded.inner_acceptance(),
            &AcceptanceV2::from_terms(&terms, rfq.initiator).unwrap()
        );
        assert!(bytes.len() <= MAX_NATIVE_ACCEPTANCE_BYTES_V25);
    }
}

#[test]
fn legacy_and_new_acceptance_codecs_never_cross_decode() {
    let (message, _) = message();
    let outer = message.canonical_bytes().unwrap();
    let inner = message.inner_acceptance().canonical_bytes().unwrap();
    assert!(AcceptanceV2::decode(&outer).is_err());
    assert!(crate::AcceptanceV1::decode(&outer).is_err());
    assert!(NativeAcceptanceV25::decode(&inner).is_err());
    assert_eq!(
        AcceptanceV2::decode(&inner).unwrap(),
        *message.inner_acceptance()
    );
}

#[test]
fn every_header_domain_version_flag_and_total_length_byte_is_closed() {
    let (message, _) = message();
    let bytes = message.canonical_bytes().unwrap();
    for index in 0..HEADER_BYTES {
        for bit in 0..8 {
            let mut changed = bytes.clone();
            changed[index] ^= 1 << bit;
            assert!(
                NativeAcceptanceV25::decode(&changed).is_err(),
                "header {index}:{bit}"
            );
        }
    }
}

#[test]
fn every_public_payload_bit_is_rejected_or_changes_expected_acceptance() {
    let (message, initiator) = message();
    let bytes = message.canonical_bytes().unwrap();
    let digest = message.message_digest().unwrap();
    for index in HEADER_BYTES..bytes.len() {
        for bit in 0..8 {
            let mut changed = bytes.clone();
            changed[index] ^= 1 << bit;
            // A modified nonzero record is still public data, but MUST NOT
            // match the expected prepared record or signed-message identity.
            if let Ok(decoded) = NativeAcceptanceV25::decode(&changed) {
                assert!(
                    decoded
                        .validate_against(message.terms(), RECORD, initiator)
                        .is_err(),
                    "payload {index}:{bit}"
                );
                assert_ne!(decoded.message_digest().unwrap(), digest);
            }
        }
    }
}

#[test]
fn all_inner_lengths_truncations_suffixes_and_overbounds_are_refused() {
    let (message, _) = message();
    let bytes = message.canonical_bytes().unwrap();
    let terms_len = message.terms().canonical_bytes().unwrap().len();
    let terms_length_offset = HEADER_BYTES + 64;
    let acceptance_length_offset = terms_length_offset + 4 + terms_len;
    for (offset, original) in [
        (terms_length_offset, terms_len),
        (acceptance_length_offset, INNER_ACCEPTANCE_BYTES),
    ] {
        for length in [0, original - 1, original + 1, u32::MAX as usize] {
            let mut changed = bytes.clone();
            changed[offset..offset + 4].copy_from_slice(&(length as u32).to_be_bytes());
            assert!(NativeAcceptanceV25::decode(&changed).is_err());
        }
    }
    for length in 0..bytes.len() {
        assert!(NativeAcceptanceV25::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(NativeAcceptanceV25::decode(&trailing).is_err());
    // Updating declared size cannot hide a suffix after the exact inner object.
    let len = u32::try_from(trailing.len()).unwrap();
    trailing[HEADER_BYTES - 4..HEADER_BYTES].copy_from_slice(&len.to_be_bytes());
    assert!(matches!(
        NativeAcceptanceV25::decode(&trailing),
        Err(F6V2Refusal::TrailingBytes)
    ));
    assert!(matches!(
        NativeAcceptanceV25::decode(&vec![0; MAX_NATIVE_ACCEPTANCE_BYTES_V25 + 1]),
        Err(F6V2Refusal::BoundExceeded)
    ));
}

#[test]
fn inner_acceptance_must_match_full_terms_and_outer_initiator() {
    let (message, _) = message();
    let mut bytes = message.canonical_bytes().unwrap();
    let inner_start = bytes.len() - INNER_ACCEPTANCE_BYTES;
    let mut inner = *message.inner_acceptance();
    inner.terms_hash[0] ^= 1;
    let changed = inner.canonical_bytes().unwrap();
    bytes[inner_start..].copy_from_slice(&changed);
    assert!(matches!(
        NativeAcceptanceV25::decode(&bytes),
        Err(F6V2Refusal::BindingMismatch)
    ));
    bytes = message.canonical_bytes().unwrap();
    inner = *message.inner_acceptance();
    inner.accepted_by = ParticipantId([3; 32]);
    bytes[inner_start..].copy_from_slice(&inner.canonical_bytes().unwrap());
    assert!(matches!(
        NativeAcceptanceV25::decode(&bytes),
        Err(F6V2Refusal::BindingMismatch)
    ));
}

#[test]
fn every_terms_field_is_part_of_expected_acceptance_not_just_its_inner_id() {
    let (message, initiator) = message();
    let original = *message.terms();
    let changes: [fn(&mut TermsBindingV2); 19] = [
        |t| t.protocol_version = 3,
        |t| t.rfq_id[0] ^= 1,
        |t| t.quote_id[0] ^= 1,
        |t| t.route.composition_id[0] ^= 1,
        |t| t.route.position = SettlementPositionV2::Downstream,
        |t| t.route.legs[0].asset.0[0] ^= 1,
        |t| t.input_asset.0[0] ^= 1,
        |t| {
            t.mode = RfqModeV1::ExactOut {
                exact_output: 95,
                maximum_input: 100,
            }
        },
        |t| t.total_fee += 1,
        |t| t.solver_id = ParticipantId([4; 32]),
        |t| t.bond_reservation_id[0] ^= 1,
        |t| t.bond_policy_version += 1,
        |t| t.execution_deadline.value += 1,
        |t| t.faces[0].refund_deadline.value += 1,
        |t| t.faces[0].payout_commitment[0] ^= 1,
        |t| t.faces[1].refund_deadline.value += 1,
        |t| t.faces[1].payout_commitment[0] ^= 1,
        |t| t.quote_expiry.value += 1,
        |t| t.session_id[0] ^= 1,
    ];
    for change in changes {
        let mut changed = original;
        change(&mut changed);
        assert!(message
            .validate_against(&changed, RECORD, initiator)
            .is_err());
        if let Ok(new_message) = NativeAcceptanceV25::new(&changed, RECORD, initiator) {
            assert_ne!(
                new_message.canonical_bytes().unwrap(),
                message.canonical_bytes().unwrap()
            );
            assert_ne!(
                new_message.message_digest().unwrap(),
                message.message_digest().unwrap()
            );
        }
    }
}

#[test]
fn missing_record_zero_identity_and_solver_as_initiator_are_refused() {
    let (message, initiator) = message();
    let terms = message.terms();
    assert!(NativeAcceptanceV25::new(terms, [0; 32], initiator).is_err());
    assert!(NativeAcceptanceV25::new(terms, RECORD, ParticipantId([0; 32])).is_err());
    assert!(NativeAcceptanceV25::new(terms, RECORD, terms.solver_id).is_err());
    let mut bytes = message.canonical_bytes().unwrap();
    bytes[HEADER_BYTES..HEADER_BYTES + 32].fill(0);
    assert!(NativeAcceptanceV25::decode(&bytes).is_err());
}

#[test]
fn public_replay_is_exact_and_cannot_cross_record_initiator_session_or_position() {
    let (message, initiator) = message();
    let decoded = NativeAcceptanceV25::decode(&message.canonical_bytes().unwrap()).unwrap();
    for _ in 0..3 {
        decoded
            .validate_against(message.terms(), RECORD, initiator)
            .unwrap();
    }
    assert!(decoded
        .validate_against(message.terms(), [0x92; 32], initiator)
        .is_err());
    assert!(decoded
        .validate_against(message.terms(), RECORD, ParticipantId([3; 32]))
        .is_err());
    let (_, _, downstream) = fixture(SettlementPositionV2::Downstream);
    assert!(decoded
        .validate_against(&downstream, RECORD, initiator)
        .is_err());
    let mut another_session = *message.terms();
    another_session.session_id = [0x93; 32];
    assert!(decoded
        .validate_against(&another_session, RECORD, initiator)
        .is_err());
    // Replay/ordering permission itself belongs to the authenticated Relay
    // journal. A public codec intentionally cannot grant or spend that right.
}
