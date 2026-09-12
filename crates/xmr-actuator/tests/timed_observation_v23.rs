//! Durable bookkeeping fixtures, not signed transactions or payment evidence.
//! No RPC/network process is started; the clock advances inside the read port.
#[path = "timed_observation_v23/checked_owner.rs"]
mod checked_owner_v23;
use std::cell::Cell;
use xmr_actuator::{
    DurableXmrActuatorV1, XmrActuatorErrorV1 as Error, XmrActuatorLeaseV1, XmrObservationPortV1,
    XmrOperationKindV1, XmrOperationLocatorV1, XmrOperationStoreV1, XmrTxInclusionV1, XmrTxStageV1,
};

fn locator() -> XmrOperationLocatorV1 {
    XmrOperationLocatorV1 {
        settlement_id: [1; 32],
        kind: XmrOperationKindV1::Refund,
    }
}
fn lease() -> XmrActuatorLeaseV1 {
    XmrActuatorLeaseV1::new([2; 32], [3; 32], [4; 32], 1, 1500).expect("lease")
}
fn prepared() -> (tempfile::TempDir, DurableXmrActuatorV1) {
    let dir = tempfile::tempdir().expect("directory");
    let actuator = DurableXmrActuatorV1::new(
        XmrOperationStoreV1::open(dir.path().join("actuator.sqlite")).expect("store"),
    );
    actuator
        .prepare_signed(&lease(), locator(), [5; 32], [6; 32], &[7; 64], 1000)
        .expect("bookkeeping row");
    (dir, actuator)
}
struct Port<'a> {
    clock: &'a Cell<u64>,
    inclusion_at: u64,
    spent_at: u64,
    inclusion: Option<XmrTxInclusionV1>,
    queries: usize,
}
impl XmrObservationPortV1 for Port<'_> {
    fn transaction_inclusion(&mut self, hash: [u8; 32]) -> Result<Option<XmrTxInclusionV1>, Error> {
        assert_eq!(hash, [5; 32]);
        self.queries += 1;
        self.clock.set(self.inclusion_at);
        Ok(self.inclusion)
    }
    fn key_image_spent(&mut self, image: [u8; 32]) -> Result<bool, Error> {
        assert_eq!(image, [6; 32]);
        self.queries += 1;
        self.clock.set(self.spent_at);
        Ok(false)
    }
}
fn inclusion() -> XmrTxInclusionV1 {
    XmrTxInclusionV1 {
        height: 100,
        block_hash: [8; 32],
        confirmations: 10,
    }
}

#[test]
fn observation_cannot_persist_with_pre_rpc_time_or_revive_expired_lease() {
    for (after, expected) in [
        (1500, Error::LeaseExpired),
        (1600, Error::LeaseExpired),
        (999, Error::InvalidTime),
    ] {
        let (_dir, actuator) = prepared();
        let before = actuator.view(locator()).expect("before");
        let clock = Cell::new(1000);
        let mut port = Port {
            clock: &clock,
            inclusion_at: after,
            spent_at: after,
            inclusion: Some(inclusion()),
            queries: 0,
        };
        let result = actuator.observe_current_with_clock_v23(
            &lease(),
            locator(),
            [9; 32],
            &mut port,
            10,
            1000,
            &mut || Ok(clock.get()),
        );
        assert_eq!(result, Err(expected));
        assert_eq!(port.queries, 1);
        assert_eq!(actuator.view(locator()).expect("after"), before);
        assert_eq!(actuator.retained(locator()).expect("bytes"), vec![7; 64]);
    }
}

#[test]
fn reconciliation_clock_covers_the_last_key_image_query() {
    let (_dir, actuator) = prepared();
    let before = actuator.view(locator()).expect("before");
    let clock = Cell::new(1000);
    let mut port = Port {
        clock: &clock,
        inclusion_at: 1100,
        spent_at: 1600,
        inclusion: None,
        queries: 0,
    };
    assert_eq!(
        actuator.reconcile_takeover_with_clock_v23(
            &lease(),
            locator(),
            [10; 32],
            &mut port,
            10,
            1000,
            &mut || Ok(clock.get())
        ),
        Err(Error::LeaseExpired)
    );
    assert_eq!(port.queries, 2);
    assert_eq!(actuator.view(locator()).expect("after"), before);
}

#[test]
fn timely_observation_is_durable_without_repeating_rpc_during_commit() {
    let (dir, actuator) = prepared();
    let clock = Cell::new(1000);
    let mut port = Port {
        clock: &clock,
        inclusion_at: 1200,
        spent_at: 1200,
        inclusion: Some(inclusion()),
        queries: 0,
    };
    let final_view = actuator
        .observe_current_with_clock_v23(
            &lease(),
            locator(),
            [11; 32],
            &mut port,
            10,
            1000,
            &mut || Ok(clock.get()),
        )
        .expect("timely observation");
    assert_eq!(port.queries, 1);
    assert_eq!(final_view.stage, XmrTxStageV1::Final);
    drop(actuator);
    let reopened = DurableXmrActuatorV1::new(
        XmrOperationStoreV1::open(dir.path().join("actuator.sqlite")).expect("reopen"),
    );
    assert_eq!(reopened.view(locator()).expect("durable final"), final_view);
    assert_eq!(
        reopened.retained(locator()).expect("same bytes"),
        vec![7; 64]
    );
}
#[test]
fn growing_confirmations_preserve_the_original_final_evidence() {
    let (_dir, actuator) = prepared();
    let clock = Cell::new(1200);
    let mut port = Port {
        clock: &clock,
        inclusion_at: 1200,
        spent_at: 1200,
        inclusion: Some(inclusion()),
        queries: 0,
    };
    let first = actuator
        .observe_current_with_clock_v23(
            &lease(),
            locator(),
            [12; 32],
            &mut port,
            10,
            1000,
            &mut || Ok(clock.get()),
        )
        .expect("first final");
    port.inclusion = Some(XmrTxInclusionV1 {
        confirmations: 20,
        ..inclusion()
    });
    let later = actuator
        .observe_current_with_clock_v23(
            &lease(),
            locator(),
            [13; 32],
            &mut port,
            10,
            1200,
            &mut || Ok(clock.get()),
        )
        .expect("same canonical inclusion");
    assert_eq!(later, first);
    assert_eq!(port.queries, 2);
}

#[test]
fn lost_changed_or_shallow_finality_is_durable_and_never_resurrected() {
    let cases = [
        None,
        Some(XmrTxInclusionV1 {
            block_hash: [19; 32],
            ..inclusion()
        }),
        Some(XmrTxInclusionV1 {
            height: 101,
            ..inclusion()
        }),
        Some(XmrTxInclusionV1 {
            confirmations: 9,
            ..inclusion()
        }),
    ];
    for reconcile in [false, true] {
        for changed in cases {
            let (dir, actuator) = prepared();
            let clock = Cell::new(1200);
            let mut port = Port {
                clock: &clock,
                inclusion_at: 1200,
                spent_at: 1600,
                inclusion: Some(inclusion()),
                queries: 0,
            };
            let first = actuator
                .observe_current_with_clock_v23(
                    &lease(),
                    locator(),
                    [14; 32],
                    &mut port,
                    10,
                    1000,
                    &mut || Ok(clock.get()),
                )
                .expect("first final");
            port.inclusion = changed;
            // Reuse the original attempt deliberately: invalidation has a
            // distinct durable mutation domain and must not replay finality.
            let invalidated = if reconcile {
                let outcome = actuator
                    .reconcile_takeover_with_clock_v23(
                        &lease(),
                        locator(),
                        [14; 32],
                        &mut port,
                        10,
                        1200,
                        &mut || Ok(clock.get()),
                    )
                    .expect("reorg reconcile");
                assert_eq!(outcome.kind, xmr_actuator::XmrReconciliationKindV1::Unknown);
                outcome.view
            } else {
                actuator
                    .observe_current_with_clock_v23(
                        &lease(),
                        locator(),
                        [14; 32],
                        &mut port,
                        10,
                        1200,
                        &mut || Ok(clock.get()),
                    )
                    .expect("reorg observe")
            };
            assert_eq!(invalidated.stage, XmrTxStageV1::FinalityInvalidated);
            assert_eq!(invalidated.finality, first.finality);
            assert_eq!(invalidated.revision, first.revision + 1);
            // A final inclusion's loss needs no key-image absence claim.
            assert_eq!(port.queries, 2);
            drop(actuator);
            let reopened = DurableXmrActuatorV1::new(
                XmrOperationStoreV1::open(dir.path().join("actuator.sqlite"))
                    .expect("reopen invalidated"),
            );
            assert_eq!(
                reopened.view(locator()).expect("durable invalidation"),
                invalidated
            );
            port.inclusion = Some(inclusion());
            let after = reopened
                .observe_current_with_clock_v23(
                    &lease(),
                    locator(),
                    [15; 32],
                    &mut port,
                    10,
                    1200,
                    &mut || Ok(clock.get()),
                )
                .expect("no resurrection");
            assert_eq!(after, invalidated);
            assert_eq!(
                reopened
                    .retained(locator())
                    .expect("retained recovery bytes"),
                vec![7; 64]
            );
        }
    }
}
