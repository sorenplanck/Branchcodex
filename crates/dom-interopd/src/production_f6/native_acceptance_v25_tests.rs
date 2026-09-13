//! Native proposal/outer-consent boundary tests with genuine opaque face owners.
//! The Relay harness verifies real BIP340 envelopes and uses DurableRelayInboxV1
//! to construct deliveries. It tests this boundary, not inventory commitment or
//! an economically complete swap. No F6PayloadDeliveryV1 is fabricated here.
use super::*;
use crate::production_f6::terms::native_terms_proposal_fixture_v25;
use relay::auth::{message_type, RosterMemberV1, RosterRegistryV1, RosterSnapshotV1};
use relay::server::RelayV1;
use relay::{RelayEnvelopeV1, SenderRoleV1, TimelockSpec};
use rfq::v2::{QuoteProposalV2, RfqRequestV2};
use route_transport::{DurableInboxConfigV1, DurableRelayInboxV1, F6DispatchErrorV1};
use std::os::unix::fs::PermissionsExt as _;

type TestResult<T = ()> = core::result::Result<T, Box<dyn std::error::Error>>;

fn receipt_directory() -> TestResult<tempfile::TempDir> {
    let root = tempfile::TempDir::new()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(root)
}

fn receipts_at(root: &std::path::Path, binding: ProductionSolverF6BindingV2) -> TestResult<Store> {
    Ok(Store::create_production(
        &root.join("proposal-receipts.sqlite"),
        ProductionStoreBindingV1::new(
            binding.authority_digest(NATIVE_INITIATOR_RECEIPTS_DOMAIN_V25)?,
        )?,
    )?)
}

fn readdress_quote(quote: QuoteV2) -> TestResult<QuoteV2> {
    Ok(QuoteV2::create(QuoteProposalV2 {
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
    })?)
}

#[test]
fn opaque_native_proposal_exact_repeat_is_stable_and_never_legacy_authority() -> TestResult {
    let fixture = native_terms_proposal_fixture_v25()?;
    let mut source = ProductionF6TermsSourceV25::native(fixture.owner);
    assert!(source.is_native());
    assert!(matches!(
        source.require_legacy(),
        Err(ProductionF6ErrorV2::InvalidTerms)
    ));
    assert!(matches!(
        source.authenticate_terms(&fixture.binding, &fixture.rfq, &fixture.quote),
        Err(ProductionF6ErrorV2::InvalidTerms)
    ));
    assert!(matches!(
        &source,
        ProductionF6TermsSourceV25::Native { prepared: None, .. }
    ));
    let root = receipt_directory()?;
    let mut receipts = receipts_at(root.path(), fixture.binding)?;
    let first = prepare_native_acceptance_v25(
        fixture.binding,
        &mut source,
        &mut receipts,
        &fixture.rfq,
        &fixture.quote,
    )?;
    let first_payload = first.canonical_bytes()?;
    let original_receipt = receipts
        .opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?
        .ok_or("native proposal receipt missing")?;
    let journal_count = receipts.read_journal()?.len();
    for _ in 0..3 {
        let repeated = prepare_native_acceptance_v25(
            fixture.binding,
            &mut source,
            &mut receipts,
            &fixture.rfq,
            &fixture.quote,
        )?;
        assert_eq!(repeated.canonical_bytes()?, first_payload);
        assert_eq!(
            receipts
                .opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?
                .as_deref(),
            Some(original_receipt.as_slice())
        );
        assert_eq!(receipts.read_journal()?.len(), journal_count);
    }
    assert!(matches!(
        source.authenticate_terms(&fixture.binding, &fixture.rfq, &fixture.quote),
        Err(ProductionF6ErrorV2::InvalidTerms)
    ));
    // Public preparation never writes the legacy authenticated-terms receipt.
    assert!(receipts
        .opaque(TERMS_NAMESPACE, &fixture.binding.rfq_id)?
        .is_none());
    Ok(())
}

#[test]
fn changed_binding_rfq_quote_or_signature_never_replaces_cached_real_proposal() -> TestResult {
    let fixture = native_terms_proposal_fixture_v25()?;
    let mut source = ProductionF6TermsSourceV25::native(fixture.owner);
    let root = receipt_directory()?;
    let mut receipts = receipts_at(root.path(), fixture.binding)?;
    let first = prepare_native_acceptance_v25(
        fixture.binding,
        &mut source,
        &mut receipts,
        &fixture.rfq,
        &fixture.quote,
    )?;
    let retained = receipts.opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?;
    let mut changed_binding = fixture.binding;
    changed_binding.wire.roster_snapshot[0] ^= 1;
    assert!(matches!(
        prepare_native_acceptance_v25(
            changed_binding,
            &mut source,
            &mut receipts,
            &fixture.rfq,
            &fixture.quote
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    let mut changed_quote = fixture.quote;
    changed_quote.total_fee += 1; // Still within the original fee ceiling.
    let changed_quote = readdress_quote(changed_quote)?;
    assert!(prepare_native_acceptance_v25(
        fixture.binding,
        &mut source,
        &mut receipts,
        &fixture.rfq,
        &changed_quote
    )
    .is_err());
    let mut changed_signature = fixture.quote;
    changed_signature.solver_signature[0] ^= 1;
    // V2 quote_id excludes its signature, but the full public record does not.
    changed_signature.validate()?;
    assert_eq!(changed_signature.quote_id, fixture.quote.quote_id);
    assert!(prepare_native_acceptance_v25(
        fixture.binding,
        &mut source,
        &mut receipts,
        &fixture.rfq,
        &changed_signature
    )
    .is_err());
    let rfq = fixture.rfq;
    let changed_rfq = RfqV2::create(RfqRequestV2 {
        initiator: rfq.initiator,
        route: rfq.route,
        mode: rfq.mode,
        fee_limit: rfq.fee_limit,
        negotiation_clock: rfq.negotiation_clock,
        quote_deadline: rfq::v2::NegotiationInstantV2 {
            clock: rfq.quote_deadline.clock,
            value: rfq.quote_deadline.value - 1,
        },
        assurance_policy_ref: rfq.assurance_policy_ref,
        policy_version: rfq.policy_version,
        session_id: rfq.session_id,
    })?;
    assert!(prepare_native_acceptance_v25(
        fixture.binding,
        &mut source,
        &mut receipts,
        &changed_rfq,
        &fixture.quote
    )
    .is_err());
    let exact = prepare_native_acceptance_v25(
        fixture.binding,
        &mut source,
        &mut receipts,
        &fixture.rfq,
        &fixture.quote,
    )?;
    assert_eq!(exact.canonical_bytes()?, first.canonical_bytes()?);
    assert_eq!(
        receipts.opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?,
        retained
    );
    Ok(())
}

#[test]
fn physical_proposal_receipt_reopen_is_immutable_and_not_an_owner_decoder() -> TestResult {
    let fixture = native_terms_proposal_fixture_v25()?;
    let mut source = ProductionF6TermsSourceV25::native(fixture.owner);
    let root = receipt_directory()?;
    let path = root.path().join("proposal-receipts.sqlite");
    let receipt_binding = ProductionStoreBindingV1::new(
        fixture
            .binding
            .authority_digest(NATIVE_INITIATOR_RECEIPTS_DOMAIN_V25)?,
    )?;
    let mut receipts = receipts_at(root.path(), fixture.binding)?;
    let first = prepare_native_acceptance_v25(
        fixture.binding,
        &mut source,
        &mut receipts,
        &fixture.rfq,
        &fixture.quote,
    )?;
    let original = receipts
        .opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?
        .ok_or("original proposal missing")?;
    drop(receipts);
    let mut reopened = Store::open_production(&path, receipt_binding)?;
    assert_eq!(
        reopened
            .opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?
            .as_deref(),
        Some(original.as_slice())
    );
    // This is a receipt-store reopening with the real owner still alive, not
    // a claim that a new process recovered adapter authority from the receipt.
    let exact = prepare_native_acceptance_v25(
        fixture.binding,
        &mut source,
        &mut reopened,
        &fixture.rfq,
        &fixture.quote,
    )?;
    assert_eq!(exact.canonical_bytes()?, first.canonical_bytes()?);
    let mut altered = original.clone();
    *altered.last_mut().ok_or("empty receipt")? ^= 1;
    assert!(matches!(
        retain_proposal(&mut reopened, fixture.binding.rfq_id, &altered),
        Err(ProductionF6ErrorV2::Receipt)
    ));
    assert_eq!(
        reopened
            .opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?
            .as_deref(),
        Some(original.as_slice())
    );
    drop((source, reopened));
    // A different freshly generated wallet yields genuine but DIFFERENT face
    // ownership. It cannot use old receipt bytes to impersonate the old wallet.
    let replacement = native_terms_proposal_fixture_v25()?;
    assert_eq!(replacement.binding, fixture.binding);
    let mut fresh = ProductionF6TermsSourceV25::native(replacement.owner);
    assert!(matches!(
        &fresh,
        ProductionF6TermsSourceV25::Native { prepared: None, .. }
    ));
    let mut reopened = Store::open_production(&path, receipt_binding)?;
    assert!(matches!(
        prepare_native_acceptance_v25(
            replacement.binding,
            &mut fresh,
            &mut reopened,
            &replacement.rfq,
            &replacement.quote
        ),
        Err(ProductionF6ErrorV2::Receipt)
    ));
    assert_eq!(
        reopened
            .opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?
            .as_deref(),
        Some(original.as_slice())
    );
    Ok(())
}

#[test]
fn native_proposal_refuses_legacy_foreign_and_development_stores_without_replacing_bytes(
) -> TestResult {
    let fixture = native_terms_proposal_fixture_v25()?;
    let mut source = ProductionF6TermsSourceV25::native(fixture.owner);
    let root = receipt_directory()?;
    let mut foreign = fixture.binding;
    foreign.wire.session_id[0] ^= 1;
    let rejected_bindings = [
        Some(fixture.binding.authority_digest(RECEIPT_BINDING_DOMAIN)?),
        Some(
            fixture
                .binding
                .authority_digest(b"DOM-INTEROP/INTEROPD/F6-INITIATOR-RECEIPTS/V25\0")?,
        ),
        Some(foreign.authority_digest(NATIVE_SOLVER_RECEIPTS_DOMAIN_V25)?),
        Some(foreign.authority_digest(NATIVE_INITIATOR_RECEIPTS_DOMAIN_V25)?),
        None, // A genuine development Store has no production identity.
    ];
    for (index, physical) in rejected_bindings.into_iter().enumerate() {
        let path = root.path().join(format!("refused-receipts-{index}.sqlite"));
        let mut receipts = match physical {
            Some(digest) => {
                Store::create_production(&path, ProductionStoreBindingV1::new(digest)?)?
            }
            None => Store::open(&path)?,
        };
        let journal_count = receipts.read_journal()?.len();
        assert!(matches!(
            prepare_native_acceptance_v25(
                fixture.binding,
                &mut source,
                &mut receipts,
                &fixture.rfq,
                &fixture.quote,
            ),
            Err(ProductionF6ErrorV2::Receipt)
        ));
        assert!(receipts
            .opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?
            .is_none());
        assert!(receipts
            .opaque(TERMS_NAMESPACE, &fixture.binding.rfq_id)?
            .is_none());
        assert_eq!(receipts.read_journal()?.len(), journal_count);

        // Preexisting public bytes must also remain untouched on refusal.
        let marker = b"preexisting data is not a native proposal or consent";
        receipts.put_opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id, marker)?;
        let journal_count = receipts.read_journal()?.len();
        assert!(matches!(
            prepare_native_acceptance_v25(
                fixture.binding,
                &mut source,
                &mut receipts,
                &fixture.rfq,
                &fixture.quote,
            ),
            Err(ProductionF6ErrorV2::Receipt)
        ));
        assert_eq!(
            receipts
                .opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?
                .as_deref(),
            Some(marker.as_slice())
        );
        assert_eq!(receipts.read_journal()?.len(), journal_count);
    }

    // Refusing a physical store does not discard the genuine cached owners.
    // Both exact native receiver identities may prepare the same unsigned data.
    let mut expected = None;
    for (index, domain) in [
        NATIVE_INITIATOR_RECEIPTS_DOMAIN_V25,
        NATIVE_SOLVER_RECEIPTS_DOMAIN_V25,
    ]
    .into_iter()
    .enumerate()
    {
        let mut receipts = Store::create_production(
            &root.path().join(format!("native-retry-{index}.sqlite")),
            ProductionStoreBindingV1::new(fixture.binding.authority_digest(domain)?)?,
        )?;
        let acceptance = prepare_native_acceptance_v25(
            fixture.binding,
            &mut source,
            &mut receipts,
            &fixture.rfq,
            &fixture.quote,
        )?;
        let bytes = acceptance.canonical_bytes()?;
        match &expected {
            Some(original) => assert_eq!(&bytes, original),
            None => expected = Some(bytes),
        }
        assert!(receipts
            .opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?
            .is_some());
        assert!(receipts
            .opaque(TERMS_NAMESPACE, &fixture.binding.rfq_id)?
            .is_none());
    }
    assert!(matches!(
        source.authenticate_terms(&fixture.binding, &fixture.rfq, &fixture.quote),
        Err(ProductionF6ErrorV2::InvalidTerms)
    ));
    Ok(())
}

const INITIATOR_SECRET: [u8; 32] = [0x52; 32];
const SOLVER_SECRET: [u8; 32] = [0x53; 32];

fn relay_roster(binding: ProductionSolverF6BindingV2) -> TestResult<RosterRegistryV1> {
    let secp = SecpContext::new(&[0x91; 32]);
    Ok(RosterRegistryV1::new().with_snapshot(
        binding.wire.roster_snapshot,
        RosterSnapshotV1::new()
            .with_member(
                binding.initiator,
                RosterMemberV1 {
                    xonly_key: secp.xonly_public_key(&INITIATOR_SECRET)?,
                    role: SenderRoleV1::Initiator,
                },
            )
            .with_member(
                binding.solver,
                RosterMemberV1 {
                    xonly_key: secp.xonly_public_key(&SOLVER_SECRET)?,
                    role: SenderRoleV1::Solver,
                },
            ),
    ))
}

fn signed_envelope(
    binding: ProductionSolverF6BindingV2,
    payload: Vec<u8>,
    kind: u16,
    solver_sender: bool,
) -> TestResult<RelayEnvelopeV1> {
    let (sender_id, recipient_id, role, secret) = if solver_sender {
        (
            binding.solver,
            binding.initiator,
            SenderRoleV1::Solver,
            SOLVER_SECRET,
        )
    } else {
        (
            binding.initiator,
            binding.solver,
            SenderRoleV1::Initiator,
            INITIATOR_SECRET,
        )
    };
    let mut envelope = RelayEnvelopeV1 {
        network_id: binding.wire.network_id,
        message_type: kind,
        session_id: binding.wire.session_id,
        route_id: binding.wire.route_id,
        sender_id,
        recipient_id,
        sender_role: role,
        sequence: 0,
        previous_transcript_hash: ZERO_DIGEST,
        payload,
        expiry: TimelockSpec::TimestampSeconds { value: 10_000 },
        policy_version: binding.wire.policy_version,
        roster_snapshot: binding.wire.roster_snapshot,
        signature: [0; 64],
    };
    envelope.signature = SecpContext::new(&[0x91; 32])
        .sign_bip340(&secret, &envelope.envelope_digest()?, &[0x92; 32])?
        .0;
    Ok(envelope)
}

struct OriginalEnvelopePort<'a> {
    binding: ProductionSolverF6BindingV2,
    source: &'a mut ProductionF6TermsSourceV25,
    receipts: &'a mut Store,
    rfq: &'a RfqV2,
    quote: &'a QuoteV2,
    calls: usize,
    original_payload: Vec<u8>,
    original_digest: Digest32,
    received: Option<AcceptanceV2>,
}

impl F6TransportPortV1 for OriginalEnvelopePort<'_> {
    type Error = ProductionF6ErrorV2;
    fn accept_f6(
        &mut self,
        delivery: F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        self.calls += 1;
        if delivery.payload() != self.original_payload.as_slice()
            || *delivery.envelope_digest() != self.original_digest
        {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        let acceptance = validate_original_native_acceptance_v25(
            self.binding,
            self.source,
            self.receipts,
            self.rfq,
            self.quote,
            &delivery,
        )?;
        self.received = Some(acceptance);
        // Durable test-boundary receipt, NOT a Bound/inventory transition.
        const NS: &[u8] = b"test-original-native-acceptance-boundary-v25";
        self.receipts
            .put_opaque_if_absent(NS, delivery.envelope_digest(), delivery.payload())
            .map_err(|_| ProductionF6ErrorV2::Receipt)?;
        if self
            .receipts
            .opaque(NS, delivery.envelope_digest())
            .map_err(|_| ProductionF6ErrorV2::Receipt)?
            .as_deref()
            != Some(delivery.payload())
        {
            return Err(ProductionF6ErrorV2::Receipt);
        }
        DurablePayloadCommitV1::new(
            DurablePayloadDispositionV1::Applied,
            *delivery.envelope_digest(),
            false,
        )
        .map_err(|_| ProductionF6ErrorV2::Receipt)
    }
}

#[test]
fn signed_outer_native_acceptance_reaches_boundary_unchanged_via_real_inbox() -> TestResult {
    let fixture = native_terms_proposal_fixture_v25()?;
    let mut source = ProductionF6TermsSourceV25::native(fixture.owner);
    let root = receipt_directory()?;
    let mut receipts = receipts_at(root.path(), fixture.binding)?;
    let expected = prepare_native_acceptance_v25(
        fixture.binding,
        &mut source,
        &mut receipts,
        &fixture.rfq,
        &fixture.quote,
    )?;
    let payload = expected.canonical_bytes()?;
    assert!(AcceptanceV2::decode(&payload).is_err());
    let envelope = signed_envelope(
        fixture.binding,
        payload.clone(),
        message_type::ACCEPTANCE,
        false,
    )?;
    let roster = relay_roster(fixture.binding)?;
    let config = DurableInboxConfigV1::new(
        [0x95; 32],
        [0x96; 32],
        fixture.binding.wire,
        fixture.binding.solver,
        16,
    )?;
    let mut inbox =
        DurableRelayInboxV1::create(&root.path().join("signed-inbox"), config, &roster)?;
    let mut relay = RelayV1::new();
    relay.submit(&envelope.canonical_bytes()?)?;
    assert_eq!(
        inbox
            .ingest_ephemeral_v1(
                &relay,
                &roster,
                TimelockSpec::TimestampSeconds { value: 1000 }
            )?
            .accepted,
        1
    );
    let mut port = OriginalEnvelopePort {
        binding: fixture.binding,
        source: &mut source,
        receipts: &mut receipts,
        rfq: &fixture.rfq,
        quote: &fixture.quote,
        calls: 0,
        original_payload: payload,
        original_digest: envelope.envelope_digest()?,
        received: None,
    };
    assert_eq!(inbox.dispatch_f6(&mut port)?.applied, 1);
    assert_eq!(port.calls, 1);
    assert_eq!(port.received, Some(*expected.inner_acceptance()));
    assert_eq!(inbox.stats()?.pending_f6, 0);
    assert_eq!(inbox.stats()?.delivered, 1);
    assert_eq!(inbox.dispatch_f6(&mut port)?.applied, 0);
    assert_eq!(port.calls, 1);
    Ok(())
}

#[test]
fn malformed_legacy_wrong_record_role_and_signature_never_authorize_native_boundary() -> TestResult
{
    let fixture = native_terms_proposal_fixture_v25()?;
    let mut source = ProductionF6TermsSourceV25::native(fixture.owner);
    let root = receipt_directory()?;
    let mut receipts = receipts_at(root.path(), fixture.binding)?;
    let expected = prepare_native_acceptance_v25(
        fixture.binding,
        &mut source,
        &mut receipts,
        &fixture.rfq,
        &fixture.quote,
    )?;
    let wrong_record =
        NativeAcceptanceV25::new(expected.terms(), [0x97; 32], fixture.binding.initiator)?;
    let mut malformed = expected.canonical_bytes()?;
    malformed.push(0);
    let roster = relay_roster(fixture.binding)?;
    let cases = [
        (
            expected.inner_acceptance().canonical_bytes()?,
            message_type::ACCEPTANCE,
            false,
            false,
        ),
        (malformed, message_type::ACCEPTANCE, false, false),
        (
            wrong_record.canonical_bytes()?,
            message_type::ACCEPTANCE,
            false,
            false,
        ),
        (expected.canonical_bytes()?, message_type::RFQ, false, false),
        (
            expected.canonical_bytes()?,
            message_type::QUOTE,
            true,
            false,
        ),
        (
            expected.canonical_bytes()?,
            message_type::ACCEPTANCE,
            true,
            false,
        ),
        (
            expected.canonical_bytes()?,
            message_type::ACCEPTANCE,
            false,
            true,
        ),
    ];
    let proposal_before = receipts.opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?;
    for (index, (payload, kind, solver_sender, invalid_signature)) in cases.into_iter().enumerate()
    {
        let mut envelope = signed_envelope(fixture.binding, payload.clone(), kind, solver_sender)?;
        if invalid_signature {
            envelope.signature[0] ^= 1;
        }
        let config = DurableInboxConfigV1::new(
            [0xa1; 32],
            [0xa2; 32],
            fixture.binding.wire,
            envelope.recipient_id,
            16,
        )?;
        let mut inbox = DurableRelayInboxV1::create(
            &root.path().join(format!("refused-inbox-{index}")),
            config,
            &roster,
        )?;
        let mut relay = RelayV1::new();
        relay.submit(&envelope.canonical_bytes()?)?;
        let ingest = inbox.ingest_ephemeral_v1(
            &relay,
            &roster,
            TimelockSpec::TimestampSeconds { value: 1000 },
        )?;
        let mut port = OriginalEnvelopePort {
            binding: fixture.binding,
            source: &mut source,
            receipts: &mut receipts,
            rfq: &fixture.rfq,
            quote: &fixture.quote,
            calls: 0,
            original_payload: payload,
            original_digest: envelope.envelope_digest()?,
            received: None,
        };
        if invalid_signature || (solver_sender && kind == message_type::ACCEPTANCE) {
            assert_eq!(ingest.accepted, 0);
            assert!(!ingest.refused.is_empty());
            assert_eq!(inbox.dispatch_f6(&mut port)?.applied, 0);
            assert_eq!(port.calls, 0);
        } else {
            assert_eq!(ingest.accepted, 1);
            assert!(matches!(
                inbox.dispatch_f6(&mut port),
                Err(F6DispatchErrorV1::F6(_))
            ));
            assert_eq!(port.calls, 1);
            assert_eq!(inbox.stats()?.pending_f6, 1);
        }
        assert!(port.received.is_none());
        assert_eq!(inbox.stats()?.delivered, 0);
        drop(port);
        assert_eq!(
            receipts.opaque(PROPOSAL_NAMESPACE, &fixture.binding.rfq_id)?,
            proposal_before
        );
    }
    Ok(())
}
