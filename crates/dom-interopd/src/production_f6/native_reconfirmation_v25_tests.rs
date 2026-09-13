//! These are public consistency regressions, NOT signed-consent or mainnet
//! acceptance tests. The constructor regressions use the shared mixed-family
//! temporal fixture and real signed-policy/evidence/store/consumption APIs.
//! No test fabricates ComposedBindingV2 fields or an authority capability.

use super::*;
use kaystra_core::types::{
    AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1, LockMechanism,
    ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId,
};
use rfq::{
    v2::{NegotiationClockV2, NegotiationInstantV2, QuoteProposalV2, RfqRequestV2, RouteV2},
    PolicyId, RouteLegV1,
};
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(PreparedNativeReconfirmationRecordV25: Clone, Copy);

fn public_inputs(
    position: SettlementPositionV2,
    exact_out: bool,
) -> (SettlementTermsV1, RouteWireContextV1, RfqV2, QuoteV2) {
    let initiator = ParticipantId([1; 32]);
    let solver = ParticipantId([2; 32]);
    let dom_chain = ChainId([3; 32]);
    let xmr_chain = ChainId([4; 32]);
    let dom_asset = AssetId([5; 32]);
    let xmr_asset = AssetId([6; 32]);
    let (dom_direction, xmr_direction, dom_amount, xmr_amount) = match position {
        SettlementPositionV2::Upstream => (
            LegDirectionV1::UserReceives,
            LegDirectionV1::UserGives,
            95,
            100,
        ),
        SettlementPositionV2::Downstream => (
            LegDirectionV1::UserGives,
            LegDirectionV1::UserReceives,
            100,
            95,
        ),
    };
    let clock = NegotiationClockV2 {
        chain_id: dom_chain,
        profile_digest: [7; 32],
        authority_scope: [8; 32],
        kind: NativeClockKindV2::BlockHeight,
    };
    let deadline = |value| NegotiationInstantV2 { clock, value };
    let wire = RouteWireContextV1 {
        network_id: [9; 32],
        route_id: [10; 32],
        session_id: [11; 32],
        roster_snapshot: [12; 32],
        policy_version: 1,
    };
    let fee_limit = FeeLimitV1 {
        dom_max: 2,
        counterparty_max: 3,
    };
    let rfq = RfqV2::create(RfqRequestV2 {
        initiator,
        route: RouteV2 {
            // This is a valid public RFQ scope, NOT a fake ComposedBindingV2.
            composition_id: [13; 32],
            position,
            legs: [
                RouteLegV1 {
                    chain_id: dom_chain,
                    asset: dom_asset,
                    direction: dom_direction,
                },
                RouteLegV1 {
                    chain_id: xmr_chain,
                    asset: xmr_asset,
                    direction: xmr_direction,
                },
            ],
        },
        mode: if exact_out {
            RfqModeV1::ExactOut {
                exact_output: 95,
                maximum_input: 100,
            }
        } else {
            RfqModeV1::ExactIn {
                input_amount: 100,
                minimum_output: 95,
            }
        },
        fee_limit,
        negotiation_clock: clock,
        quote_deadline: deadline(900),
        assurance_policy_ref: PolicyId([14; 32]),
        policy_version: 1,
        session_id: wire.session_id,
    })
    .unwrap();
    let quote = QuoteV2::create(QuoteProposalV2 {
        rfq_id: rfq.rfq_id,
        solver,
        route: rfq.route,
        net_output: 95,
        total_input: 100,
        total_fee: 5,
        execution_deadline: deadline(950),
        bond_reservation_id: [15; 32],
        bond_policy_version: 1,
        expiry: deadline(925),
        // Deliberately NOT an authenticated signature. Public preparation may
        // retain it, but cannot treat it as consent or mint an authority.
        solver_signature: [0; 64],
    })
    .unwrap();
    let leg = |role, chain_id, asset_id, amount, mechanism, deadline| LegTermsV1 {
        role,
        chain_id,
        asset_id,
        amount,
        beneficiary: solver,
        refund_to: initiator,
        mechanism,
        deadline,
        finality: FinalityPolicyV1 {
            min_confirmations: 3,
            max_reorg_depth: 6,
        },
        adapter_profile_hash: [16; 32],
    };
    let original = SettlementTermsV1 {
        settlement_id: SettlementId([17; 32]),
        session_id: SessionId(wire.session_id),
        intent_hash: IntentHash([18; 32]),
        solver_id: SolverId(solver.0),
        roster: [initiator, solver],
        dom_leg: leg(
            LegRole::Dom,
            dom_chain,
            dom_asset,
            dom_amount,
            LockMechanism::DomAdaptor2of2,
            TimelockSpec::BlockHeight { value: 1000 },
        ),
        counterparty_leg: leg(
            LegRole::Counterparty,
            xmr_chain,
            xmr_asset,
            xmr_amount,
            LockMechanism::CrossCurveSharedSpend,
            TimelockSpec::BlockHeight { value: 20 },
        ),
        adaptor_point_sec1: [2; 33],
        fee_limit,
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 120,
        },
        assurance_policy_hash: Some(rfq.assurance_policy_ref.0),
        policy_version: 1,
        metadata: vec![21, 22],
    };
    original.validate().unwrap();
    (original, wire, rfq, quote)
}

fn readdress_quote(quote: QuoteV2) -> QuoteV2 {
    QuoteV2::create(QuoteProposalV2 {
        rfq_id: quote.rfq_id,
        solver: quote.solver,
        route: quote.route,
        net_output: quote.net_output,
        total_input: quote.total_input,
        total_fee: quote.total_fee,
        execution_deadline: quote.execution_deadline,
        bond_reservation_id: quote.bond_reservation_id,
        bond_policy_version: quote.bond_policy_version,
        expiry: quote.expiry,
        solver_signature: quote.solver_signature,
    })
    .unwrap()
}

#[test]
fn public_checks_cover_both_positions_and_modes_without_rewriting_intent() {
    for position in [
        SettlementPositionV2::Upstream,
        SettlementPositionV2::Downstream,
    ] {
        for exact_out in [false, true] {
            let (original, wire, rfq, quote) = public_inputs(position, exact_out);
            let before = original.canonical_bytes().unwrap();
            assert_ne!(original.intent_hash.0, rfq.rfq_id);
            validate_public_economics(&original, wire, position, &rfq, &quote).unwrap();
            assert_eq!(original.canonical_bytes().unwrap(), before);
            assert_eq!(quote.solver_signature, [0; 64]);
        }
    }
}

#[test]
fn altered_original_economics_and_authority_scope_are_refused() {
    let position = SettlementPositionV2::Upstream;
    let (original, wire, rfq, quote) = public_inputs(position, false);
    let mutations: [fn(&mut SettlementTermsV1); 9] = [
        |t| t.dom_leg.amount += 1,
        |t| t.counterparty_leg.amount += 1,
        |t| t.fee_limit.dom_max += 1,
        |t| t.solver_id = SolverId([31; 32]),
        |t| t.roster[1] = ParticipantId([32; 32]),
        |t| t.assurance_policy_hash = Some([33; 32]),
        |t| t.session_id = SessionId([34; 32]),
        |t| t.policy_version += 1,
        |t| t.dom_leg.asset_id = AssetId([35; 32]),
    ];
    for change in mutations {
        let mut altered = original.clone();
        change(&mut altered);
        assert!(validate_public_economics(&altered, wire, position, &rfq, &quote).is_err());
    }
    assert!(validate_public_economics(
        &original,
        wire,
        SettlementPositionV2::Downstream,
        &rfq,
        &quote
    )
    .is_err());
    let mut foreign = wire;
    foreign.session_id = [36; 32];
    assert!(validate_public_economics(&original, foreign, position, &rfq, &quote).is_err());
}

#[test]
fn canonical_but_changed_quote_cannot_change_original_amounts_or_fee_cap() {
    let position = SettlementPositionV2::Downstream;
    let (original, wire, rfq, quote) = public_inputs(position, false);
    for change in [(101, 95, 5), (100, 96, 5), (100, 95, 6)] {
        let mut altered = quote;
        (altered.total_input, altered.net_output, altered.total_fee) = change;
        let altered = readdress_quote(altered);
        assert!(validate_public_economics(&original, wire, position, &rfq, &altered).is_err());
    }
}

#[test]
fn deadlines_require_same_dom_clock_without_comparing_foreign_heights() {
    let position = SettlementPositionV2::Upstream;
    let (original, wire, rfq, quote) = public_inputs(position, false);
    // The foreign height 20 is intentionally below DOM's 950; cross-chain
    // ordering cannot be inferred by comparing the integers.
    validate_public_economics(&original, wire, position, &rfq, &quote).unwrap();
    let mut late = quote;
    late.execution_deadline.value = 1001;
    assert_eq!(
        validate_public_economics(&original, wire, position, &rfq, &readdress_quote(late)),
        Err(NativeReconfirmationRefusalV25::DeadlineMismatch)
    );
    let mut changed_clock = original.clone();
    changed_clock.dom_leg.deadline = TimelockSpec::TimestampSeconds { value: 1000 };
    assert_eq!(
        validate_public_economics(&changed_clock, wire, position, &rfq, &quote),
        Err(NativeReconfirmationRefusalV25::DeadlineMismatch)
    );
}

#[test]
fn noncanonical_ids_and_missing_reservation_are_never_accepted_as_public_inputs() {
    let position = SettlementPositionV2::Upstream;
    let (original, wire, rfq, quote) = public_inputs(position, false);
    let mut altered = quote;
    altered.quote_id[0] ^= 1;
    assert!(validate_public_economics(&original, wire, position, &rfq, &altered).is_err());
    altered = quote;
    altered.bond_reservation_id = [0; 32];
    assert!(validate_public_economics(&original, wire, position, &rfq, &altered).is_err());
    let mut altered_rfq = rfq;
    altered_rfq.rfq_id[0] ^= 1;
    assert!(validate_public_economics(&original, wire, position, &altered_rfq, &quote).is_err());
}

#[test]
fn bounded_encoding_is_length_delimited_and_digest_binds_every_public_byte() {
    let mut first = Vec::new();
    append_bounded(&mut first, &[1]).unwrap();
    append_bounded(&mut first, &[2, 3]).unwrap();
    let mut second = Vec::new();
    append_bounded(&mut second, &[1, 2]).unwrap();
    append_bounded(&mut second, &[3]).unwrap();
    assert_ne!(first, second);
    let original = public_record_digest(&first).unwrap();
    assert_ne!(original, public_record_digest(&second).unwrap());
    for index in 0..first.len() {
        let mut changed = first.clone();
        changed[index] ^= 1;
        assert_ne!(original, public_record_digest(&changed).unwrap());
    }
    let mut full = vec![0; MAX_RECORD_BYTES - 4];
    append_bounded(&mut full, &[]).unwrap();
    let before = full.clone();
    assert!(append_bounded(&mut full, &[1]).is_err());
    assert_eq!(full, before);
}

/// Same authenticated temporal construction used by production input tests.
/// The source fixture is EVM -> DOM -> BTC: these tests prove the public
/// record's composition binding, not native-XMR enrollment or signed consent.
fn real_compositions() -> (tempfile::TempDir, ComposedBindingV2, ComposedBindingV2) {
    use crate::route_time_test_common as common;
    use route_time_anchor::{
        DurableRouteTimeAnchorStoreV2, RouteTimeAnchorStoreConfigV2, RouteTimePolicyV2,
    };

    let mut fixture = common::fixture();
    // A new test negotiation, before policy/evidence signatures or composition
    // construction. Nothing previously signed or admitted is rewritten.
    for (index, terms) in [&mut fixture.upstream, &mut fixture.downstream]
        .into_iter()
        .enumerate()
    {
        terms.solver_id = SolverId(terms.roster[1].0);
        terms.assurance_policy_hash = Some([0xe1; 32]);
        terms.metadata = vec![0xe2, index as u8, 0xe3];
    }
    fixture.policy = RouteTimePolicyV2::from_registry(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        common::limits(),
    )
    .expect("new policy for the complete original negotiated terms");
    let root = tempfile::TempDir::new().expect("isolated temporal store");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private temporal directory");
    }
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .expect("production temporal store binding");
    let mut store = DurableRouteTimeAnchorStoreV2::create(
        &root.path().join("reconfirmation-time.sqlite"),
        config,
    )
    .expect("production temporal store");
    store
        .install_policy(
            &common::signed_policy(&fixture),
            fixture.policy_context(),
            common::EVIDENCE_TIME,
        )
        .expect("verify actual threshold policy signatures");
    let evidence = common::evidence(&fixture.policy, 1, common::EVIDENCE_TIME, 0);
    store
        .install_evidence(
            &common::signed_evidence(&fixture, &evidence),
            fixture.evidence_context(),
            common::EVIDENCE_TIME,
        )
        .expect("verify actual threshold evidence signatures");
    let mut compose_at = |now| {
        let proof = store
            .prove_route_ladder(fixture.evidence_context(), now)
            .expect("verify complete route-time ladder");
        let current = store
            .consume_capability_at(proof, now)
            .expect("consume current proof with opening/revision/freshness guards");
        ComposedBindingV2::bind(
            fixture.upstream.clone(),
            fixture.downstream.clone(),
            current,
        )
        .expect("real immutable composed binding")
    };
    let first = compose_at(common::EVIDENCE_TIME);
    let later = compose_at(common::EVIDENCE_TIME + 1);
    assert_ne!(first.binding_digest(), later.binding_digest());
    assert_eq!(first.upstream(), later.upstream());
    assert_eq!(first.downstream(), later.downstream());
    (root, first, later)
}

fn proposals_for_composition(
    composition: &ComposedBindingV2,
    position: SettlementPositionV2,
    exact_out: bool,
) -> (RouteWireContextV1, RfqV2, QuoteV2) {
    let original = match position {
        SettlementPositionV2::Upstream => composition.upstream(),
        SettlementPositionV2::Downstream => composition.downstream(),
    };
    let (dom_direction, counterparty_direction, total_input, net_output) = match position {
        SettlementPositionV2::Upstream => (
            LegDirectionV1::UserReceives,
            LegDirectionV1::UserGives,
            original.counterparty_leg.amount,
            original.dom_leg.amount,
        ),
        SettlementPositionV2::Downstream => (
            LegDirectionV1::UserGives,
            LegDirectionV1::UserReceives,
            original.dom_leg.amount,
            original.counterparty_leg.amount,
        ),
    };
    let dom_deadline = match original.dom_leg.deadline {
        TimelockSpec::BlockHeight { value } => value,
        _ => panic!("shared fixture requires a native DOM height"),
    };
    let wire = RouteWireContextV1 {
        network_id: crate::route_time_test_common::REGISTRY_NETWORK,
        route_id: [0xe4; 32],
        session_id: original.session_id.0,
        roster_snapshot: [0xe5; 32],
        policy_version: original.policy_version,
    };
    let clock = NegotiationClockV2 {
        chain_id: original.dom_leg.chain_id,
        profile_digest: original.dom_leg.adapter_profile_hash,
        authority_scope: composition.time_policy_digest(),
        kind: NativeClockKindV2::BlockHeight,
    };
    let rfq = RfqV2::create(RfqRequestV2 {
        initiator: original.roster[0],
        route: RouteV2 {
            composition_id: composition.binding_digest(),
            position,
            legs: [
                RouteLegV1 {
                    chain_id: original.dom_leg.chain_id,
                    asset: original.dom_leg.asset_id,
                    direction: dom_direction,
                },
                RouteLegV1 {
                    chain_id: original.counterparty_leg.chain_id,
                    asset: original.counterparty_leg.asset_id,
                    direction: counterparty_direction,
                },
            ],
        },
        mode: if exact_out {
            RfqModeV1::ExactOut {
                exact_output: net_output,
                maximum_input: total_input,
            }
        } else {
            RfqModeV1::ExactIn {
                input_amount: total_input,
                minimum_output: net_output,
            }
        },
        fee_limit: original.fee_limit,
        negotiation_clock: clock,
        quote_deadline: NegotiationInstantV2 {
            clock,
            value: dom_deadline - 10,
        },
        assurance_policy_ref: PolicyId(original.assurance_policy_hash.unwrap()),
        policy_version: original.policy_version,
        session_id: original.session_id.0,
    })
    .expect("content-addressed RFQ commits the actual composition");
    let quote = QuoteV2::create(QuoteProposalV2 {
        rfq_id: rfq.rfq_id,
        solver: original.roster[1],
        route: rfq.route,
        net_output,
        total_input,
        total_fee: 1,
        execution_deadline: NegotiationInstantV2 {
            clock,
            value: dom_deadline - 1,
        },
        bond_reservation_id: [0xe6; 32],
        bond_policy_version: original.policy_version,
        expiry: NegotiationInstantV2 {
            clock,
            value: dom_deadline - 5,
        },
        solver_signature: [0; 64],
    })
    .expect("public unsigned proposal, not an actual reserved/consented quote");
    (wire, rfq, quote)
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> &'a [u8] {
    let start = *cursor;
    *cursor = start.checked_add(len).expect("test cursor overflow");
    bytes.get(start..*cursor).expect("complete canonical field")
}

fn take_part<'a>(bytes: &'a [u8], cursor: &mut usize) -> &'a [u8] {
    let length = u32::from_be_bytes(take(bytes, cursor, 4).try_into().unwrap());
    take(bytes, cursor, length as usize)
}

fn assert_exact_record_sources(
    record: &PreparedNativeReconfirmationRecordV25,
    composition: &ComposedBindingV2,
    wire: RouteWireContextV1,
    position: SettlementPositionV2,
    rfq: &RfqV2,
    quote: &QuoteV2,
) {
    let original = match position {
        SettlementPositionV2::Upstream => composition.upstream(),
        SettlementPositionV2::Downstream => composition.downstream(),
    };
    let bytes = record.canonical_bytes();
    let mut cursor = 0;
    assert_eq!(take(bytes, &mut cursor, 8), MAGIC);
    assert_eq!(take(bytes, &mut cursor, 2), &VERSION.to_be_bytes());
    assert_eq!(take(bytes, &mut cursor, 2), &[0, 0]);
    for field in [
        wire.network_id,
        wire.route_id,
        wire.session_id,
        wire.roster_snapshot,
    ] {
        assert_eq!(take(bytes, &mut cursor, 32), &field);
    }
    assert_eq!(
        take(bytes, &mut cursor, 4),
        &wire.policy_version.to_be_bytes()
    );
    let tag = match position {
        SettlementPositionV2::Upstream => 1,
        SettlementPositionV2::Downstream => 2,
    };
    assert_eq!(take(bytes, &mut cursor, 1), &[tag]);
    for field in [
        original.intent_hash.0,
        rfq.rfq_id,
        quote.quote_id,
        quote.bond_reservation_id,
    ] {
        assert_eq!(take(bytes, &mut cursor, 32), &field);
    }
    for participant in original.roster {
        assert_eq!(take(bytes, &mut cursor, 32), &participant.0);
    }
    for field in [
        composition.binding_digest(),
        composition.route_scope_digest(),
        composition.time_policy_digest(),
        composition.time_evidence_digest(),
        composition.time_proof_digest(),
    ] {
        assert_eq!(take(bytes, &mut cursor, 32), &field);
    }
    assert_eq!(
        take(bytes, &mut cursor, 8),
        &composition.evidence_sequence().to_be_bytes()
    );
    for terms in [composition.upstream(), composition.downstream()] {
        let retained = take_part(bytes, &mut cursor);
        assert_eq!(retained, terms.canonical_bytes().unwrap().as_slice());
        assert_eq!(SettlementTermsV1::decode(retained).unwrap(), *terms);
    }
    assert_eq!(
        take_part(bytes, &mut cursor),
        rfq.canonical_bytes().unwrap().as_slice()
    );
    assert_eq!(
        take_part(bytes, &mut cursor),
        quote.canonical_bytes().unwrap().as_slice()
    );
    assert_eq!(cursor, bytes.len());
    assert!(bytes.len() <= MAX_RECORD_BYTES);
    assert_eq!(record.digest(), public_record_digest(bytes).unwrap());
}

#[test]
fn real_signed_temporal_composition_constructs_and_retains_every_original_byte() {
    let (_root, composition, _later) = real_compositions();
    let originals = [
        composition.upstream().canonical_bytes().unwrap(),
        composition.downstream().canonical_bytes().unwrap(),
    ];
    for position in [
        SettlementPositionV2::Upstream,
        SettlementPositionV2::Downstream,
    ] {
        for exact_out in [false, true] {
            let (wire, rfq, quote) = proposals_for_composition(&composition, position, exact_out);
            let record = PreparedNativeReconfirmationRecordV25::prepare(
                &composition,
                wire,
                position,
                &rfq,
                &quote,
            )
            .unwrap();
            assert_exact_record_sources(&record, &composition, wire, position, &rfq, &quote);
            assert_ne!(composition.upstream().intent_hash.0, rfq.rfq_id);
            let replay = PreparedNativeReconfirmationRecordV25::prepare(
                &composition,
                wire,
                position,
                &rfq,
                &quote,
            )
            .unwrap();
            assert_eq!(record.canonical_bytes(), replay.canonical_bytes());
            assert_eq!(record.digest(), replay.digest());
        }
    }
    assert_eq!(
        composition.upstream().canonical_bytes().unwrap(),
        originals[0]
    );
    assert_eq!(
        composition.downstream().canonical_bytes().unwrap(),
        originals[1]
    );
}

#[test]
fn another_real_composition_cannot_reuse_original_rfq_even_with_identical_terms() {
    let (_root, first, later) = real_compositions();
    let position = SettlementPositionV2::Upstream;
    let (wire, rfq, quote) = proposals_for_composition(&first, position, false);
    let first_record =
        PreparedNativeReconfirmationRecordV25::prepare(&first, wire, position, &rfq, &quote)
            .unwrap();
    assert!(matches!(
        PreparedNativeReconfirmationRecordV25::prepare(&later, wire, position, &rfq, &quote),
        Err(NativeReconfirmationRefusalV25::ScopeMismatch)
    ));
    let (later_wire, later_rfq, later_quote) = proposals_for_composition(&later, position, false);
    let later_record = PreparedNativeReconfirmationRecordV25::prepare(
        &later,
        later_wire,
        position,
        &later_rfq,
        &later_quote,
    )
    .unwrap();
    assert_ne!(first_record.digest(), later_record.digest());
    assert_ne!(rfq.rfq_id, later_rfq.rfq_id);
    assert_eq!(first.upstream().intent_hash, later.upstream().intent_hash);
}
