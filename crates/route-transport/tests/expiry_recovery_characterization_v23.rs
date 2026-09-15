//! Characterization of the existing V1 protocol, not expiry-renewal support.
//! Real sender/Relay/inbox stores and BIP340 outer signatures are used. Opaque
//! fixture payloads are not economic DSC1 artifacts or funding signatures.
#![cfg(target_os = "linux")]

use std::{error::Error, os::unix::fs::PermissionsExt};

use btc_crypto::SecpContext;
use relay::auth::{AuthRefusal, RosterMemberV1, RosterRegistryV1, RosterSnapshotV1};
use relay::production::{
    DeliveryPageLimitsV3, DeliveryScopeV3, ProductionRelayV1, RelayDatabaseConfigV1,
    RelayDatabaseIdV1,
};
use relay::server::{AckV1, RelayV1};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec};
use route_transport::{
    BridgeRefusal, DurableInboxConfigV1, DurableInboxEnvelopeRefusalV1, DurableRelayInboxV1,
    DurableRelaySenderConfigV1, DurableRelaySenderErrorV1, DurableRelaySenderV1,
    RelaySubmitQueueV1, RouteApplicationDispositionV2, RouteWireContextV1,
};

const SENDER: ParticipantId = ParticipantId([1; 32]);
const RECIPIENT: ParticipantId = ParticipantId([2; 32]);
const SECRET: [u8; 32] = [3; 32];
const RELAY_DATABASE: [u8; 32] = [4; 32];
const APPLICATION: [u8; 32] = [5; 32];
const PAYLOAD: &[u8] = b"opaque transport-only characterization payload";
const FIRST_ACCEPTANCE: u64 = 1_000;
const ORIGINAL_EXPIRY: u64 = FIRST_ACCEPTANCE + 3_600;
const AFTER_EXPIRY: u64 = ORIGINAL_EXPIRY + 3_601;
type TestResult = Result<(), Box<dyn Error>>;

fn time(value: u64) -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value }
}

fn wire() -> RouteWireContextV1 {
    RouteWireContextV1 {
        network_id: [10; 32],
        session_id: [11; 32],
        route_id: [12; 32],
        roster_snapshot: [13; 32],
        policy_version: 1,
    }
}

fn xonly() -> Result<[u8; 32], Box<dyn Error>> {
    Ok(SecpContext::new(&[14; 32])
        .sign_bip340(&SECRET, &[0; 32], &[0; 32])?
        .1)
}

fn rosters() -> Result<RosterRegistryV1, Box<dyn Error>> {
    Ok(RosterRegistryV1::new().with_snapshot(
        wire().roster_snapshot,
        RosterSnapshotV1::new().with_member(
            SENDER,
            RosterMemberV1 {
                xonly_key: xonly()?,
                role: SenderRoleV1::Initiator,
            },
        ),
    ))
}

fn sender_config() -> Result<DurableRelaySenderConfigV1, Box<dyn Error>> {
    Ok(DurableRelaySenderConfigV1::new(
        [15; 32],
        wire(),
        SENDER,
        RECIPIENT,
        SenderRoleV1::Initiator,
        xonly()?,
        16,
    )?)
}

fn relay_config() -> Result<RelayDatabaseConfigV1, Box<dyn Error>> {
    Ok(RelayDatabaseConfigV1::new(
        RelayDatabaseIdV1::new(RELAY_DATABASE)?,
        16,
    )?)
}

fn inbox_config() -> Result<DurableInboxConfigV1, Box<dyn Error>> {
    Ok(DurableInboxConfigV1::new(
        [16; 32],
        RELAY_DATABASE,
        wire(),
        RECIPIENT,
        16,
    )?)
}

fn temporary() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(temporary)
}

struct LoseStorageAck<'a> {
    relay: &'a mut ProductionRelayV1,
    stored_ack: Option<AckV1>,
}

impl RelaySubmitQueueV1 for LoseStorageAck<'_> {
    fn queue_submit(&mut self, raw: &[u8]) -> Result<AckV1, BridgeRefusal> {
        self.stored_ack = Some(
            self.relay
                .submit(raw)
                .map_err(BridgeRefusal::DurableRelay)?,
        );
        // Inject loss only AFTER the real Relay's durable commit. The sender
        // receives no usable receipt and must retain its original pending row.
        Err(BridgeRefusal::AckDigestMismatch)
    }
}

#[test]
fn accepted_before_expiry_recovers_lost_acks_after_all_stores_reopen_v23() -> TestResult {
    let temporary = temporary()?;
    let sender_root = temporary.path().join("sender");
    let relay_root = temporary.path().join("relay");
    let inbox_root = temporary.path().join("inbox");
    let rosters = rosters()?;
    let mut sender =
        DurableRelaySenderV1::create(&sender_root, sender_config()?, SECRET, [17; 32])?;
    let mut relay = ProductionRelayV1::create(&relay_root, relay_config()?)?;
    let mut inbox = DurableRelayInboxV1::create(&inbox_root, inbox_config()?, &rosters)?;
    sender.prepare_route_application(APPLICATION, PAYLOAD, time(ORIGINAL_EXPIRY), [18; 32])?;
    let exact = sender
        .pending_envelope()?
        .ok_or("pending envelope")?
        .canonical_bytes()
        .to_vec();
    let original = RelayEnvelopeV1::decode(&exact)?;
    let original_ack = {
        let mut queue = LoseStorageAck {
            relay: &mut relay,
            stored_ack: None,
        };
        assert!(matches!(
            sender.submit_pending(&mut queue),
            Err(DurableRelaySenderErrorV1::Queue(_))
        ));
        queue.stored_ack.ok_or("Relay persisted its ACK")?
    };
    assert_eq!(sender.checkpoint()?.next_sequence(), 0);
    assert_eq!(
        relay.stored_bytes(&original_ack.key)?.as_deref(),
        Some(exact.as_slice())
    );

    let scope = DeliveryScopeV3::new(RECIPIENT, wire().route_id, wire().session_id)?;
    let cursor = relay.acknowledged_delivery_cursor_v3(&scope)?;
    let page = relay.delivery_page_v3(
        &scope,
        &cursor,
        DeliveryPageLimitsV3::new(1, relay::MAX_ENVELOPE_BYTES as u32)?,
    )?;
    assert_eq!(page.envelopes(), [exact.clone()]);
    let next_cursor = *page.next_cursor();
    // Exercise the same durable ingest_one authority while deliberately NOT
    // acknowledging the pinned production page. This test seam models the
    // crash boundary after inbox persistence and before page ACK; it is not
    // a claim to have killed a live Noise daemon at that instruction.
    let mut replay_mailbox = RelayV1::new();
    replay_mailbox.submit(&exact)?;
    let accepted = inbox.ingest_ephemeral_v1(&replay_mailbox, &rosters, time(FIRST_ACCEPTANCE))?;
    assert_eq!((accepted.accepted, accepted.duplicates), (1, 0));
    assert!(accepted.refused.is_empty());
    assert_eq!(relay.acknowledged_delivery_cursor_v3(&scope)?, cursor);
    let original_stats = inbox.stats()?;
    drop(inbox);
    drop(relay);
    drop(sender);

    let mut sender =
        DurableRelaySenderV1::open_existing(&sender_root, sender_config()?, SECRET, [19; 32])?;
    let mut relay = ProductionRelayV1::open(&relay_root, relay_config()?)?;
    // Reopen audits accepted_now from the actual old durable acceptance. It
    // does not use a caller-supplied fake historic clock to admit new bytes.
    let mut inbox = DurableRelayInboxV1::open(&inbox_root, inbox_config()?, &rosters)?;
    assert!(
        matches!(original.expiry, TimelockSpec::TimestampSeconds { value } if AFTER_EXPIRY > value)
    );
    assert!(matches!(
        sender.prepare_route_application(
            APPLICATION,
            PAYLOAD,
            time(AFTER_EXPIRY + 3_600),
            [20; 32]
        )?,
        RouteApplicationDispositionV2::Pending(_)
    ));
    let pending = sender
        .pending_envelope()?
        .ok_or("retained pending envelope")?;
    assert_eq!(pending.canonical_bytes(), exact);
    assert_eq!(
        RelayEnvelopeV1::decode(pending.canonical_bytes())?.expiry,
        original.expiry
    );
    let commit = sender.submit_pending(&mut relay)?;
    assert_eq!(
        commit.ack().canonical_bytes(),
        original_ack.canonical_bytes()
    );
    assert_eq!(sender.checkpoint()?.next_sequence(), 1);
    assert!(sender.pending_envelope()?.is_none());
    assert!(matches!(
        sender.prepare_route_application(
            APPLICATION,
            PAYLOAD,
            time(AFTER_EXPIRY + 3_600),
            [21; 32]
        )?,
        RouteApplicationDispositionV2::AlreadyAcked(_)
    ));
    assert_eq!(sender.checkpoint()?.next_sequence(), 1);

    let duplicate = inbox.ingest(&mut relay, &rosters, time(AFTER_EXPIRY))?;
    assert_eq!((duplicate.accepted, duplicate.duplicates), (0, 1));
    assert!(duplicate.refused.is_empty());
    assert_eq!(inbox.stats()?, original_stats);
    assert_eq!(relay.acknowledged_delivery_cursor_v3(&scope)?, next_cursor);
    assert_eq!(relay.len()?, 0);
    // Even after delivery GC, retained flow receipts preserve the exact ACK.
    assert_eq!(
        relay.submit(&exact)?.canonical_bytes(),
        original_ack.canonical_bytes()
    );
    assert_eq!(inbox.stats()?.pending_route, 1);
    assert_eq!(
        inbox.stats()?.delivered,
        0,
        "no economic consumer invoked by this test"
    );
    Ok(())
}

#[test]
fn never_accepted_expired_head_is_quarantined_and_fresh_successor_cannot_skip_it_v23() -> TestResult
{
    let temporary = temporary()?;
    let sender_root = temporary.path().join("sender");
    let relay_root = temporary.path().join("relay");
    let inbox_root = temporary.path().join("inbox");
    let rosters = rosters()?;
    let mut sender =
        DurableRelaySenderV1::create(&sender_root, sender_config()?, SECRET, [22; 32])?;
    let mut relay = ProductionRelayV1::create(&relay_root, relay_config()?)?;
    sender.prepare_route_application(APPLICATION, PAYLOAD, time(ORIGINAL_EXPIRY), [23; 32])?;
    sender.submit_pending(&mut relay)?;
    // A storage ACK is NOT recipient authentication: nothing was ingested
    // before this first recipient observation, over one hour after expiry.
    let mut inbox = DurableRelayInboxV1::create(&inbox_root, inbox_config()?, &rosters)?;
    let refused = inbox.ingest(&mut relay, &rosters, time(AFTER_EXPIRY))?;
    assert_eq!(
        (refused.accepted, refused.duplicates, refused.quarantined),
        (0, 0, 1)
    );
    assert!(matches!(
        refused.refused.as_slice(),
        [DurableInboxEnvelopeRefusalV1::Pipeline(
            AuthRefusal::Expired
        )]
    ));
    assert_eq!(
        (inbox.stats()?.pending_route, inbox.stats()?.delivered),
        (0, 0)
    );
    // Re-staging the same inner application cannot secretly renew expiry or
    // allocate a replacement outer sequence, even though Relay ACKed it.
    assert!(matches!(
        sender.prepare_route_application(
            APPLICATION,
            PAYLOAD,
            time(AFTER_EXPIRY + 3_600),
            [24; 32]
        )?,
        RouteApplicationDispositionV2::AlreadyAcked(_)
    ));
    assert_eq!(sender.checkpoint()?.next_sequence(), 1);
    sender.prepare_route_application(
        [25; 32],
        b"different successor transport fixture",
        time(AFTER_EXPIRY + 3_600),
        [26; 32],
    )?;
    sender.submit_pending(&mut relay)?;
    let gap = inbox.ingest(&mut relay, &rosters, time(AFTER_EXPIRY))?;
    assert_eq!((gap.accepted, gap.quarantined), (0, 1));
    assert!(matches!(
        gap.refused.as_slice(),
        [DurableInboxEnvelopeRefusalV1::Pipeline(
            AuthRefusal::SequenceGap
        )]
    ));
    let retained = inbox.stats()?;
    assert_eq!(
        (
            retained.pending_route,
            retained.delivered,
            retained.quarantined
        ),
        (0, 0, 2)
    );
    drop(inbox);
    let inbox = DurableRelayInboxV1::open(&inbox_root, inbox_config()?, &rosters)?;
    assert_eq!(inbox.stats()?, retained);
    Ok(())
}
