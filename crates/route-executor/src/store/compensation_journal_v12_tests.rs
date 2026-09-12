//! Deterministic codec/reducer and real SQLite crash/reopen tests. The positive
//! ledger test enters the private already-verified ingress; it does not replace
//! or claim to test native chain verification in the productive entry point.

use super::*;
use crate::model::{
    ActionIntentV1, ActionKindV1, ActionStateV1, DomCompensationRecordV12, EffectDispatchV1,
    FrozenBindingsV1, LegIdV1, RefundBindingsV1,
};
use crate::HealthStateV1;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;

fn record() -> DomCompensationRecordV12 {
    DomCompensationRecordV12 {
        dom_chain_id: [1; 32],
        session_id: [2; 32],
        terms_digest: [3; 32],
        graph_digest: [4; 32],
        funding_transaction_id: [5; 32],
        transaction_id: [6; 32],
        evidence_digest: [7; 32],
        policy_hash: [8; 32],
        custody_id: [9; 32],
        recipient: [10; 32],
        payout_noms: 1_100,
    }
}
fn funding_intent() -> ActionIntentV1 {
    ActionIntentV1 {
        leg: LegIdV1::Upstream,
        kind: ActionKindV1::Funding,
        semantic_digest: [20; 32],
        contains_route_secret: false,
        dispatch: EffectDispatchV1::ExternalCustody {
            custody_digest: [21; 32],
            transaction_id: [22; 32],
        },
    }
}

#[test]
fn legacy_snapshots_keep_exact_v1_encoding_and_empty_compensated_encoding_is_rejected() {
    let initial = RouteSnapshotV1::new([1; 32]).expect("route");
    let old = initial.encode_canonical().expect("old encoding");
    assert_eq!(&old[..4], b"DRS1");
    let decoded = RouteSnapshotV1::decode_canonical(&old).expect("old decode");
    assert!(decoded.upstream.dom_compensation_v12.is_none());
    assert_eq!(decoded.encode_canonical().expect("roundtrip"), old);
    let mut invalid = old;
    invalid[..4].copy_from_slice(b"DRS2");
    invalid.extend_from_slice(&[0, 0]);
    assert!(RouteSnapshotV1::decode_canonical(&invalid).is_err());
}

#[test]
fn compensation_is_atomic_distinct_and_replayable_but_raw_event_acceptance_is_forbidden(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    #[cfg(target_os = "linux")]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("route.sqlite");
    let mut store = DurableRouteStoreV1::create(&path)?;
    store.create_route([1; 32], 1)?;
    let lease = store.acquire_lease([1; 32], [2; 32], 2, 10_000)?.lease();
    let events = [
        RouteEventV1::FreezeTerms(FrozenBindingsV1 {
            terms_digest: [3; 32],
            profile_bundle_digest: [4; 32],
            deployment_bundle_digest: [5; 32],
        }),
        RouteEventV1::ArmRefunds(RefundBindingsV1 {
            upstream_refund_digest: [6; 32],
            downstream_refund_digest: [7; 32],
        }),
        RouteEventV1::CommitAction(funding_intent()),
    ];
    for (index, event) in events.iter().enumerate() {
        store.apply_event(
            lease,
            index as u64,
            [30 + index as u8; 32],
            event,
            3 + index as u64,
        )?;
    }
    let event = RouteEventV1::DomCompensatedV12 {
        leg: LegIdV1::Upstream,
        compensation: record(),
    };
    let encoded = event.encode_canonical()?;
    let decoded = RouteEventV1::decode_canonical(&encoded)?;
    assert_eq!(
        store.apply_event(lease, 3, [40; 32], &decoded, 6),
        Err(RouteStoreErrorV1::InvalidMaterial)
    );
    assert_eq!(store.pending_effect_count([1; 32])?, 1);
    store.apply_event_from_native_owner_v12(lease, 3, [40; 32], &event, 6)?;
    let accepted = store.verify_replay([1; 32])?;
    assert_eq!(
        accepted.upstream.dom_compensation_v12.as_ref(),
        Some(&record())
    );
    assert!(accepted.upstream.is_terminal());
    assert_eq!(accepted.upstream.refund, ActionStateV1::NotPrepared);
    assert_eq!(accepted.upstream.claim, ActionStateV1::NotPrepared);
    assert_eq!(accepted.secret_visibility, SecretVisibilityV1::Private);
    assert_eq!(&accepted.encode_canonical()?[..4], b"DRS2");
    assert_eq!(store.pending_effect_count([1; 32])?, 0);
    drop(store);
    let mut reopened = DurableRouteStoreV1::open_existing(&path)?;
    assert_eq!(reopened.verify_replay([1; 32])?, accepted);
    assert_eq!(
        reopened.apply_event_from_native_owner_v12(lease, 3, [40; 32], &event, 7)?,
        CommitOutcomeV1::DuplicateSameBytes { revision: 4 }
    );
    assert!(reopened
        .apply_event(
            lease,
            4,
            [41; 32],
            &RouteEventV1::CommitAction(funding_intent()),
            8
        )
        .is_err());
    assert!(reopened
        .apply_event(
            lease,
            4,
            [42; 32],
            &RouteEventV1::SetHealth {
                target: HealthStateV1::Running,
                reason_digest: [43; 32]
            },
            9
        )
        .is_err());
    Ok(())
}
