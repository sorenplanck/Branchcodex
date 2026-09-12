//! Codec/filter and real durable Relay framing regressions. The opaque frame
//! fixture is NOT a native refund proof or a Contracts Store authority.
//! Store handoff is covered separately by the real Store integration tests;
//! these tests do not replace the native Store/daemon recovery scenario.
use super::*;
use xmr_remote_sweep_wire::{RemoteSweepActionV23, RemoteSweepLegV23, RemoteSweepRequestV23};

fn request(action: RemoteSweepActionV23) -> RemoteSweepRequestV23 {
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
        public_secret_evidence_digest: [15; 32],
        funding_tx_hash: [16; 32],
        funding_evidence_digest: [17; 32],
        public_spend_share: [18; 32],
        funding_output_index: 1,
        funding_block_height: 100,
        funded_amount_piconero: 5_000_000,
        max_fee_piconero: 50_000,
        adapter_max_raw_transaction_bytes: 512 * 1024,
        max_raw_transaction_bytes: 128 * 1024,
        fencing_epoch: 9,
        action,
        leg: RemoteSweepLegV23::Upstream,
        destination: "48bWuoDG75vE6cX7cD4zNQeZg1V23canonicalDestination".into(),
    }
}

#[test]
fn terminal_filter_accepts_only_canonical_refund_request_not_claim_or_other_dsc1() {
    let refund = request(RemoteSweepActionV23::Refund).encode().unwrap();
    require_public_refund_payload_v24(MessageTypeV1::XmrRemoteSweepRequestV23, &refund).unwrap();
    let claim = request(RemoteSweepActionV23::Claim).encode().unwrap();
    assert!(matches!(
        require_public_refund_payload_v24(MessageTypeV1::XmrRemoteSweepRequestV23, &claim),
        Err(ContractsRelayIngressErrorV1::UnpreparedMessage)
    ));
    for value in 1..=0x18 {
        let kind = MessageTypeV1::try_from(value).unwrap();
        assert!(matches!(
            require_public_refund_payload_v24(kind, &refund),
            Err(ContractsRelayIngressErrorV1::UnpreparedMessage)
        ));
    }
}

#[test]
fn terminal_filter_never_treats_malformed_public_payload_as_absent() {
    let refund = request(RemoteSweepActionV23::Refund).encode().unwrap();
    for length in 0..refund.len() {
        assert!(matches!(
            require_public_refund_payload_v24(
                MessageTypeV1::XmrRemoteSweepRequestV23,
                &refund[..length]
            ),
            Err(ContractsRelayIngressErrorV1::InvalidDsc1)
        ));
    }
    let mut trailing = refund;
    trailing.push(0);
    assert!(
        require_public_refund_payload_v24(MessageTypeV1::XmrRemoteSweepRequestV23, &trailing)
            .is_err()
    );
    assert!(matches!(
        require_public_refund_payload_v24(MessageTypeV1::XmrRemoteSweepResponseV23, &[]),
        Err(ContractsRelayIngressErrorV1::InvalidDsc1)
    ));
}

#[test]
fn terminal_ingress_never_dispatches_f6_and_frame_retry_never_creates_application() {
    let source = include_str!("relay_worker.rs");
    let poll = source
        .split("pub(crate) fn poll_terminal_refund_inbound_v24(")
        .nth(1)
        .unwrap()
        .split("/// Compatibility-only poll")
        .next()
        .unwrap();
    assert!(!poll.contains("dispatch_f6"));
    assert!(poll.contains(".dispatch_routes("));
    assert!(poll.contains("terminal_refund_only_v24 = true"));
    let submit = source
        .split("pub(crate) fn submit_terminal_refund_outbound_v24<")
        .nth(1)
        .unwrap()
        .split("pub(crate) fn terminal_refund_frames_pending_v24")
        .next()
        .unwrap();
    let existing = submit.find(".route_application_status(").unwrap();
    let staged = submit.find(".stage_store_outbound_dsc1(").unwrap();
    assert!(
        existing < staged,
        "terminal staging must first prove the original application exists"
    );
    assert!(submit.contains("SigningRequest(request)"));
    assert!(submit.contains("request.message_type() == 0x1a"));
    let acknowledged = submit
        .find("if matches!(submitted, RelayOutboundStepV1::Acked")
        .unwrap();
    let restaged = submit.rfind(".stage_store_outbound_dsc1(").unwrap();
    assert!(staged < acknowledged && acknowledged < restaged);
    assert!(submit[acknowledged..restaged].contains(".resume_outbound_dsc1(session)"));
    assert!(submit[acknowledged..restaged].contains("retained.application_id() != &application_id"));
    assert!(submit[acknowledged..restaged].contains("retained.message_digest() != &message_digest"));
    let handoff = source
        .split("pub fn stage_store_outbound_dsc1(")
        .nth(1)
        .unwrap()
        .split("/// Submits at most one exact durable envelope.")
        .next()
        .unwrap();
    assert!(
        handoff
            .find(".revalidate_committed_outbound_dsc1(")
            .unwrap()
            < handoff.find(".prepare_route_application(").unwrap()
    );
    let acked = handoff
        .find("RouteApplicationDispositionV2::AlreadyAcked(_)")
        .unwrap();
    assert!(handoff[acked..].contains(".complete_outbound_dsc1_relay_handoff(outbound)"));
}

#[cfg(target_os = "linux")]
#[test]
fn terminal_multiframe_reopen_keeps_original_expiry_and_exact_acknowledged_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    use btc_crypto::SecpContext;
    use relay::production::{ProductionRelayV1, RelayDatabaseConfigV1, RelayDatabaseIdV1};
    use relay::RelayEnvelopeV1;
    use route_transport::{
        RouteApplicationStateV2, RouteFrameV2, RouteWireContextV1,
        MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES,
    };

    let temporary = tempfile::tempdir()?;
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
    let sender_root = temporary.path().join("sender");
    let relay_root = temporary.path().join("relay");
    let wire = RouteWireContextV1 {
        network_id: [0x11; 32],
        session_id: [0x22; 32],
        route_id: [0x33; 32],
        roster_snapshot: [0x44; 32],
        policy_version: 1,
    };
    let local = ParticipantId([0x51; 32]);
    let remote = ParticipantId([0x61; 32]);
    let secret = [0x71; 32];
    let public = SecpContext::new(&[0x19; 32])
        .sign_bip340(&secret, &[0; 32], &[0; 32])?
        .1;
    let config = DurableRelaySenderConfigV1::new(
        [0x81; 32],
        wire,
        local,
        remote,
        SenderRoleV1::Initiator,
        public,
        16,
    )?;
    let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 16)?;
    let mut sender = DurableRelaySenderV1::create(&sender_root, config, secret, [1; 32])?;
    let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
    let application = [0xa1; 32];
    // Transport deliberately treats DSC1 bytes as opaque. Do not claim this
    // large framing fixture is an economically admissible native response.
    let opaque = vec![0x5c; 2 * MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES + 17];
    let original_expiry = TimelockSpec::BlockHeight { value: 10_000 };
    let forbidden_renewal = TimelockSpec::TimestampSeconds { value: u64::MAX };
    let initial =
        sender.prepare_route_application(application, &opaque, original_expiry, [2; 32])?;
    let initial = initial.status();
    assert!(initial.frame_count() > 1);
    let mut reconstructed = Vec::new();
    let mut previous_digest = [0; 32];
    for index in 0..initial.frame_count() {
        // On later rounds the previous frame is ACKed and there is NO pending
        // envelope. Re-staging the retained application must prepare the next
        // reserved frame, not return Idle and strand the rest of the message.
        let resumed =
            sender.prepare_route_application(application, &opaque, forbidden_renewal, [3; 32])?;
        assert!(matches!(resumed, RouteApplicationDispositionV2::Pending(_)));
        assert_eq!(resumed.status().acknowledged_frames(), index);
        let exact = sender
            .pending_envelope()?
            .expect("next original frame")
            .canonical_bytes()
            .to_vec();
        let envelope = RelayEnvelopeV1::decode(&exact)?;
        assert_eq!(envelope.expiry, original_expiry);
        assert_eq!(envelope.sequence, u64::from(index));
        assert_eq!(envelope.previous_transcript_hash, previous_digest);
        let digest = envelope.envelope_digest()?;
        relay::auth::verify_roster_signature(&public, &digest, &envelope.signature)?;
        let frame = RouteFrameV2::decode_for_flow(&envelope.payload, wire, local, remote)?;
        assert_eq!(frame.index(), index);
        assert_eq!(frame.count(), initial.frame_count());
        reconstructed.extend_from_slice(frame.chunk());
        let checkpoint = sender.checkpoint()?;

        // Actual Relay commit followed by owner drop/reopen to model a lost
        // ACK before the sender can consume it. No queue mock invents an ACK;
        // this regression does not launch or kill a daemon process.
        relay.submit(&exact)?;
        drop(sender);
        drop(relay);
        sender = DurableRelaySenderV1::open_existing(&sender_root, config, secret, [4; 32])?;
        relay = ProductionRelayV1::open(&relay_root, relay_config)?;
        sender.prepare_route_application(application, &opaque, forbidden_renewal, [5; 32])?;
        assert_eq!(sender.pending_envelope()?.unwrap().canonical_bytes(), exact);
        assert_eq!(sender.checkpoint()?, checkpoint);
        let committed = sender.submit_pending(&mut relay)?;
        assert_eq!(committed.ack().digest, digest);
        assert_eq!(relay.len()?, usize::from(index) + 1);
        assert!(sender.pending_envelope()?.is_none());
        let progress = sender.route_application_status(application)?.unwrap();
        assert_eq!(progress.acknowledged_frames(), index + 1);
        assert_eq!(progress.first_sequence(), initial.first_sequence());
        assert_eq!(progress.final_sequence(), initial.final_sequence());
        assert_eq!(
            sender.frame_transfer_status()?.is_some(),
            index + 1 < initial.frame_count()
        );
        previous_digest = digest;
        // Also restart in the ACK→next-frame window which exposed the drain
        // bug, and after the final ACK before Store handoff reconciliation.
        drop(sender);
        drop(relay);
        sender = DurableRelaySenderV1::open_existing(&sender_root, config, secret, [6; 32])?;
        relay = ProductionRelayV1::open(&relay_root, relay_config)?;
    }
    assert_eq!(reconstructed, opaque);
    let checkpoint = sender.checkpoint()?;
    let stats = sender.stats()?;
    let final_status =
        sender.prepare_route_application(application, &opaque, forbidden_renewal, [7; 32])?;
    assert!(matches!(
        final_status,
        RouteApplicationDispositionV2::AlreadyAcked(_)
    ));
    assert_eq!(
        final_status.status().state(),
        RouteApplicationStateV2::Acked
    );
    assert_eq!(
        final_status.status().acknowledged_frames(),
        initial.frame_count()
    );
    assert_eq!(sender.checkpoint()?, checkpoint);
    assert_eq!(sender.stats()?, stats);
    assert!(!stats.pending && !stats.framed_transfer_active);
    assert_eq!(stats.completed, u32::from(initial.frame_count()));
    assert_eq!(checkpoint.next_sequence(), u64::from(initial.frame_count()));
    assert_eq!(relay.len()?, usize::from(initial.frame_count()));
    Ok(())
}
