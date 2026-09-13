//! Genuine signed-time composition plus real wallet/store and EVM deployment
//! face constructors. The shared fixture is mixed-family, not a native-XMR
//! acceptance test. No private face fields or authority tokens are fabricated.
use super::*;
use crate::production_f6::{ProductionF6PinsV2, ProductionF6TermsAuthorityV2 as _};
use crate::route_time_test_common as common;
use dom_actuator::{
    DomActuatorStoreV1, DomParticipantV1, DomParticipantWalletV1, DomPayoutFaceSelectionRequestV1,
    DomSessionBindingV1, DomWalletAuthorityBindingV1, DomWalletSessionLegV1,
};
use kaystra_core::types::{ParticipantId, SolverId};
use rfq::v2::{
    NativeClockKindV2, NegotiationClockV2, NegotiationInstantV2, QuoteProposalV2, RfqRequestV2,
    RouteV2,
};
use rfq::{LegDirectionV1, PolicyId, RfqModeV1, RouteLegV1};
use route_time_anchor::{
    DurableRouteTimeAnchorStoreV2, RouteTimeAnchorStoreConfigV2, RouteTimePolicyV2,
};
use route_transport::RouteWireContextV1;
use static_assertions::assert_not_impl_any;
use std::os::unix::fs::PermissionsExt as _;

assert_not_impl_any!(ProductionNativeF6TermsProposalOwnerV25: Clone, Copy, core::fmt::Debug);
assert_not_impl_any!(PreparedNativeF6TermsProposalV25: Clone, Copy, core::fmt::Debug);
assert_not_impl_any!(ProductionNativeF6TermsProposalOwnerV25: crate::production_f6::ProductionF6TermsAuthorityV2);

type TestResult<T = ()> = core::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct NativeTermsProposalFixtureV25 {
    _root: tempfile::TempDir,
    pub(crate) composition: Rc<ComposedBindingV2>,
    pub(crate) binding: ProductionSolverF6BindingV2,
    pub(crate) rfq: RfqV2,
    pub(crate) quote: QuoteV2,
    pub(crate) owner: ProductionNativeF6TermsProposalOwnerV25,
}

pub(crate) fn native_terms_proposal_fixture_v25() -> TestResult<NativeTermsProposalFixtureV25> {
    let mut fixture = common::fixture();
    // New negotiation before signing policy/evidence; original terms remain
    // frozen after this point and never receive an RFQ-derived replacement ID.
    for terms in [&mut fixture.upstream, &mut fixture.downstream] {
        terms.solver_id = SolverId(terms.roster[1].0);
        terms.assurance_policy_hash = Some([0x81; 32]);
    }
    fixture.policy = RouteTimePolicyV2::from_registry(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        common::limits(),
    )?;
    let root = tempfile::TempDir::new()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )?;
    let mut time = DurableRouteTimeAnchorStoreV2::create(&root.path().join("time.sqlite"), config)?;
    time.install_policy(
        &common::signed_policy(&fixture),
        fixture.policy_context(),
        common::EVIDENCE_TIME,
    )?;
    let evidence = common::evidence(&fixture.policy, 1, common::EVIDENCE_TIME, 0);
    time.install_evidence(
        &common::signed_evidence(&fixture, &evidence),
        fixture.evidence_context(),
        common::EVIDENCE_TIME,
    )?;
    let proof = time.prove_route_ladder(fixture.evidence_context(), common::EVIDENCE_TIME)?;
    let current = time.consume_capability_at(proof, common::EVIDENCE_TIME)?;
    let composition = Rc::new(ComposedBindingV2::bind(
        fixture.upstream.clone(),
        fixture.downstream.clone(),
        current,
    )?);
    let original = composition.upstream();
    let wire = RouteWireContextV1 {
        network_id: common::REGISTRY_NETWORK,
        session_id: original.session_id.0,
        route_id: [0x82; 32],
        roster_snapshot: [0x83; 32],
        policy_version: original.policy_version,
    };
    let clock = NegotiationClockV2 {
        chain_id: original.dom_leg.chain_id,
        profile_digest: original.dom_leg.adapter_profile_hash,
        authority_scope: composition.time_policy_digest(),
        kind: NativeClockKindV2::BlockHeight,
    };
    let instant = |value| NegotiationInstantV2 { clock, value };
    let rfq = RfqV2::create(RfqRequestV2 {
        initiator: original.roster[0],
        route: RouteV2 {
            composition_id: composition.binding_digest(),
            position: SettlementPositionV2::Upstream,
            legs: [
                RouteLegV1 {
                    chain_id: original.counterparty_leg.chain_id,
                    asset: original.counterparty_leg.asset_id,
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: original.dom_leg.chain_id,
                    asset: original.dom_leg.asset_id,
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        },
        mode: RfqModeV1::ExactIn {
            input_amount: original.counterparty_leg.amount,
            minimum_output: original.dom_leg.amount,
        },
        fee_limit: original.fee_limit,
        negotiation_clock: clock,
        quote_deadline: instant(190),
        assurance_policy_ref: PolicyId(original.assurance_policy_hash.ok_or("assurance absent")?),
        policy_version: original.policy_version,
        session_id: original.session_id.0,
    })?;
    let quote = QuoteV2::create(QuoteProposalV2 {
        rfq_id: rfq.rfq_id,
        solver: original.roster[1],
        route: rfq.route,
        net_output: original.dom_leg.amount,
        total_input: original.counterparty_leg.amount,
        total_fee: 1,
        execution_deadline: instant(195),
        bond_reservation_id: [0x84; 32],
        bond_policy_version: original.policy_version,
        expiry: instant(192),
        solver_signature: [0; 64],
    })?;
    let pins = ProductionF6PinsV2 {
        inventory_binding_digest: [0x85; 32],
        registry_digest: fixture.registry.manifest_digest(),
        registry_epoch: fixture.registry.epoch(),
        profile_bundle_digest: [0x86; 32],
        bond_policy_hash: original.assurance_policy_hash.ok_or("assurance absent")?,
        bond_asset_binding_digest: [0x87; 32],
        required_collateral: 50,
        bond_attestation_authority_set_digest: [0x88; 32],
        remote_status_authority_set_digest: [0x89; 32],
        solver_status_scope_digest: [0x8a; 32],
        pre_f6_time_scope_digest: [0x8b; 32],
    };
    // Pins/RFQ/quote above are public preparation inputs. They assert no
    // observed inventory, signed quote, accepted reservation or F6 consent.
    let binding = ProductionSolverF6BindingV2::new(
        wire,
        &rfq,
        quote.solver,
        original.dom_leg.chain_id,
        pins,
    )?;
    let dom_deployment = fixture.registry.resolve_dom()?;
    // The signed time policy freezes the complete registry-derived DOM
    // profile. The wallet separately pins consensus rules; these domains must
    // never be substituted merely to make the adapter face pass admission.
    assert_eq!(
        original.dom_leg.adapter_profile_hash,
        route_time_anchor::resolved_dom_profile_digest_v1(&fixture.registry)?,
    );
    assert_eq!(
        original.dom_leg.adapter_profile_hash,
        route_time_anchor::resolved_dom_deployment_profile_digest_v25(dom_deployment)?,
    );
    assert_ne!(
        original.dom_leg.adapter_profile_hash,
        dom_deployment.deployment().consensus_rules_digest,
    );
    let participant = DomParticipantV1::new(original.dom_leg.beneficiary.0, 1)?;
    let upstream = DomSessionBindingV1::from_resolved_deployment(
        wire.route_id,
        original.session_id.0,
        participant,
        original.terms_hash()?,
        dom_deployment,
    )?;
    let downstream = DomSessionBindingV1::from_resolved_deployment(
        wire.route_id,
        composition.downstream().session_id.0,
        participant,
        composition.downstream().terms_hash()?,
        dom_deployment,
    )?;
    let wallet_path = root.path().join("wallet.v3");
    let empty = dom_wallet2::WalletV2State::new(dom_wallet2::Network::Regtest, upstream.chain_id());
    dom_wallet2::save_wallet_state(&empty, &wallet_path, "proposal-fixture-only")?;
    std::fs::set_permissions(&wallet_path, std::fs::Permissions::from_mode(0o600))?;
    let mut store = DomActuatorStoreV1::create(&root.path().join("actuator.sqlite"))?;
    let lease = store.acquire_lease(participant.participant_id(), [0x8c; 32], 1000, 10_000)?;
    store.bind_session(lease, upstream, 1000)?;
    store.bind_session(lease, downstream, 1000)?;
    let mut wallet = DomParticipantWalletV1::open_existing(
        &wallet_path,
        zeroize::Zeroizing::new("proposal-fixture-only".into()),
        DomWalletAuthorityBindingV1::new(upstream, downstream)?,
    )?;
    // Real wallet-generated payout, real blinding/proof, encrypted persistence
    // and store receipt. No AuthenticatedDomPayoutFaceV1 field is fabricated.
    let payout = wallet
        .session(DomWalletSessionLegV1::Upstream)?
        .prepare_unique_payout_face_v16(
            &mut store,
            lease,
            DomPayoutFaceSelectionRequestV1::new(u64::try_from(original.dom_leg.amount)?, 1001)?,
        )?;
    let dom = AdapterAuthenticatedRefundFaceV2::from_dom(
        payout,
        &binding,
        original,
        &composition,
        dom_deployment,
    )
    .map_err(|error| format!("native proposal fixture DOM payout face: {error}"))?;
    let evm = fixture
        .registry
        .resolve_chain(original.counterparty_leg.chain_id)
        .ok_or("original EVM chain absent")?
        .evm_deployment_capability(
            original.counterparty_leg.asset_id,
            deployment_registry::EvmSessionBindingsV1 {
                direction: adapter_evm::Direction::EvmToDom,
                session_id: original.session_id.0,
                terms_hash: original.terms_hash()?,
                participants_hash: participant_binding::evm_participants_hash_v1(original.roster)?,
                beneficiary: [0x8d; 20],
                funder: [0x8e; 20],
            },
        )?;
    let counterparty = AdapterAuthenticatedRefundFaceV2::from_evm(&binding, original, evm)
        .map_err(|error| format!("native proposal fixture EVM refund face: {error}"))?;
    let owner = ProductionNativeF6TermsProposalOwnerV25::new(
        binding,
        Rc::clone(&composition),
        dom,
        counterparty,
    )
    .map_err(|error| format!("native proposal fixture composed face owner: {error}"))?;
    Ok(NativeTermsProposalFixtureV25 {
        _root: root,
        composition,
        binding,
        rfq,
        quote,
        owner,
    })
}

#[test]
fn dom_registry_profile_is_not_wallet_consensus_and_wrong_domain_is_refused() -> TestResult {
    let fixture = common::fixture();
    let deployment = fixture.registry.resolve_dom()?;
    let profile = route_time_anchor::resolved_dom_deployment_profile_digest_v25(deployment)?;
    assert_eq!(
        profile,
        route_time_anchor::resolved_dom_profile_digest_v1(&fixture.registry)?,
    );
    assert_eq!(profile, fixture.upstream.dom_leg.adapter_profile_hash);
    assert_ne!(profile, deployment.deployment().consensus_rules_digest);
    RouteTimePolicyV2::from_registry(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        common::limits(),
    )?;
    // Neither a plausible nonzero consensus digest nor the registry manifest
    // digest can replace the exact profile authenticated by signed time policy.
    for wrong_domain in [
        deployment.deployment().consensus_rules_digest,
        deployment.registry_digest(),
    ] {
        let mut upstream = fixture.upstream.clone();
        let mut downstream = fixture.downstream.clone();
        upstream.dom_leg.adapter_profile_hash = wrong_domain;
        downstream.dom_leg.adapter_profile_hash = wrong_domain;
        assert!(matches!(
            RouteTimePolicyV2::from_registry(
                &fixture.registry,
                &upstream,
                &downstream,
                common::limits(),
            ),
            Err(route_time_anchor::RouteTimeAnchorErrorV2::RegistryMismatch)
        ));
    }
    Ok(())
}

fn changed_quote(quote: QuoteV2, total_fee: u128, net_output: u128) -> TestResult<QuoteV2> {
    Ok(QuoteV2::create(QuoteProposalV2 {
        rfq_id: quote.rfq_id,
        solver: quote.solver,
        route: quote.route,
        net_output,
        total_input: quote.total_input,
        total_fee,
        execution_deadline: quote.execution_deadline,
        bond_reservation_id: quote.bond_reservation_id,
        bond_policy_version: quote.bond_policy_version,
        expiry: quote.expiry,
        solver_signature: quote.solver_signature,
    })?)
}

#[test]
fn real_faces_and_signed_time_prepare_only_native_proposal_legacy_still_refuses() -> TestResult {
    let mut f = native_terms_proposal_fixture_v25()?;
    let original_terms = f.composition.upstream().canonical_bytes()?;
    assert_ne!(f.composition.upstream().intent_hash.0, f.rfq.rfq_id);
    let legacy = f
        .owner
        .original
        .as_mut()
        .ok_or("owner missing")?
        .authenticate_terms(&f.binding, &f.rfq, &f.quote);
    assert!(matches!(legacy, Err(ProductionF6ErrorV2::InvalidTerms)));
    assert!(f
        .owner
        .original
        .as_ref()
        .is_some_and(|owner| owner.dom.is_some() && owner.counterparty.is_some()));
    let proposal = f.owner.prepare(&f.binding, &f.rfq, &f.quote)?;
    assert_eq!(proposal.binding(), f.binding);
    assert_eq!(
        proposal.composition().binding_digest(),
        f.composition.binding_digest()
    );
    assert_eq!(proposal.terms().rfq_id, f.rfq.rfq_id);
    assert_eq!(proposal.terms().quote_id, f.quote.quote_id);
    assert_ne!(proposal.proposal_evidence_digest(), [0; 32]);
    assert!(proposal.proposal_evidence_revision() > 0);
    let record = PreparedNativeReconfirmationRecordV25::prepare(
        &f.composition,
        f.binding.wire,
        f.binding.position,
        &f.rfq,
        &f.quote,
    )
    .map_err(|_| "public record reconstruction")?;
    assert_eq!(
        proposal.record().canonical_bytes(),
        record.canonical_bytes()
    );
    assert_eq!(proposal.record().digest(), record.digest());
    assert_eq!(f.composition.upstream().canonical_bytes()?, original_terms);
    assert!(matches!(
        f.owner.prepare(&f.binding, &f.rfq, &f.quote),
        Err(ProductionF6ErrorV2::TermsUnavailable)
    ));
    // These remain the actual opaque owners, not commitment-only reconstructions.
    assert!(proposal.original.dom.is_some() && proposal.original.counterparty.is_some());
    Ok(())
}

#[test]
fn public_economic_and_scope_failures_preserve_real_faces_for_exact_retry() -> TestResult {
    let mut f = native_terms_proposal_fixture_v25()?;
    let too_expensive = changed_quote(f.quote, 21, f.quote.net_output)?;
    let changed_amount = changed_quote(f.quote, f.quote.total_fee, f.quote.net_output + 1)?;
    for quote in [too_expensive, changed_amount] {
        assert!(f.owner.prepare(&f.binding, &f.rfq, &quote).is_err());
        assert!(f
            .owner
            .original
            .as_ref()
            .is_some_and(|owner| owner.dom.is_some() && owner.counterparty.is_some()));
    }
    let mut wrong_binding = f.binding;
    wrong_binding.wire.roster_snapshot[0] ^= 1;
    assert!(f.owner.prepare(&wrong_binding, &f.rfq, &f.quote).is_err());
    wrong_binding = f.binding;
    wrong_binding.position = SettlementPositionV2::Downstream;
    assert!(f.owner.prepare(&wrong_binding, &f.rfq, &f.quote).is_err());
    let mut wrong_rfq = f.rfq;
    wrong_rfq.rfq_id[0] ^= 1;
    assert!(f.owner.prepare(&f.binding, &wrong_rfq, &f.quote).is_err());
    let proposal = f.owner.prepare(&f.binding, &f.rfq, &f.quote)?;
    let consent_data = rfq::native_reconfirmation_v25::NativeAcceptanceV25::new(
        proposal.terms(),
        proposal.record().digest(),
        f.rfq.initiator,
    )?;
    consent_data.validate_against(
        proposal.terms(),
        proposal.record().digest(),
        f.rfq.initiator,
    )?;
    assert!(consent_data
        .validate_against(proposal.terms(), [0x8f; 32], f.rfq.initiator)
        .is_err());
    assert!(consent_data
        .validate_against(
            proposal.terms(),
            proposal.record().digest(),
            ParticipantId([1; 32])
        )
        .is_err());
    // Public acceptance data is deliberately not promoted to a signed delivery
    // or grant. Authentication belongs to the consumer of the original envelope.
    Ok(())
}
