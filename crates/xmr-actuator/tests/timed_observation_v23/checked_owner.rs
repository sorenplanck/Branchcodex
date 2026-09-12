//! Bookkeeping-only regressions: no signing, RPC process, or payment proof.
use super::*;

fn make_final(actuator: &DurableXmrActuatorV1) {
    let clock = Cell::new(1100);
    let mut port = Port {
        clock: &clock,
        inclusion_at: 1100,
        spent_at: 1100,
        inclusion: Some(inclusion()),
        queries: 0,
    };
    actuator
        .observe_current_with_clock_v23(
            &lease(),
            locator(),
            [31; 32],
            &mut port,
            10,
            1000,
            &mut || Ok(clock.get()),
        )
        .expect("final bookkeeping");
}

#[test]
fn stable_final_result_rejects_wrong_network_before_query() {
    let (_dir, actuator) = prepared();
    make_final(&actuator);
    let before = actuator.view(locator()).expect("before");
    let wrong =
        XmrActuatorLeaseV1::new([2; 32], [3; 32], [99; 32], 1, 1500).expect("wrong network lease");
    let clock = Cell::new(1200);
    let mut port = Port {
        clock: &clock,
        inclusion_at: 1200,
        spent_at: 1200,
        inclusion: Some(inclusion()),
        queries: 0,
    };
    assert_eq!(
        actuator.observe_current_with_clock_v23(
            &wrong,
            locator(),
            [32; 32],
            &mut port,
            10,
            1100,
            &mut || Ok(clock.get())
        ),
        Err(Error::Conflict)
    );
    assert_eq!(port.queries, 0);
    assert_eq!(actuator.view(locator()).expect("unchanged"), before);
}

struct ChangeDuringQuery<'a> {
    path: &'a std::path::Path,
    change_owner: bool,
    change_revision: bool,
    queries: usize,
}
impl XmrObservationPortV1 for ChangeDuringQuery<'_> {
    fn transaction_inclusion(&mut self, hash: [u8; 32]) -> Result<Option<XmrTxInclusionV1>, Error> {
        assert_eq!(hash, [5; 32]);
        self.queries += 1;
        let connection = rusqlite::Connection::open(self.path).expect("race connection");
        if self.change_owner {
            connection
                .execute(
                    "UPDATE universal_actuator_owner_v11 SET epoch=2 WHERE singleton=1",
                    [],
                )
                .expect("replace physical owner");
        } else if self.change_revision {
            connection
                .execute("UPDATE xmr_operation_v1 SET revision=revision+1", [])
                .expect("concurrent operation revision");
        } else {
            // Deliberate corruption to prove the cached response cannot be
            // applied to a different immutable transaction after the RPC.
            connection
                .execute(
                    "UPDATE xmr_operation_v1 SET tx_hash=?1",
                    rusqlite::params![[44u8; 32].as_slice()],
                )
                .expect("tamper immutable identity");
        }
        Ok(Some(inclusion()))
    }
    fn key_image_spent(&mut self, _: [u8; 32]) -> Result<bool, Error> {
        panic!("included final transaction needs no key-image query")
    }
}

#[test]
fn final_read_rechecks_physical_owner_and_immutable_identity_after_rpc() {
    for reconcile in [false, true] {
        for (change_owner, change_revision) in [(false, false), (true, false), (false, true)] {
            let (dir, actuator) = prepared();
            make_final(&actuator);
            let before = actuator.view(locator()).expect("before");
            drop(actuator);
            let path = dir.path().join("actuator.sqlite");
            let connection = rusqlite::Connection::open(&path).expect("owner registry");
            connection
                .execute_batch(
                    "CREATE TABLE universal_actuator_owner_v11(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),binding BLOB NOT NULL,
                family INTEGER NOT NULL,epoch INTEGER NOT NULL);",
                )
                .expect("registry schema");
            connection
                .execute(
                    "INSERT INTO universal_actuator_owner_v11 VALUES(1,?1,4,1)",
                    rusqlite::params![[7u8; 32].as_slice()],
                )
                .expect("original owner");
            drop(connection);
            let actuator = DurableXmrActuatorV1::new(
                XmrOperationStoreV1::open_existing_fenced_v12(&path, [7; 32], 1)
                    .expect("fenced open"),
            );
            let mut port = ChangeDuringQuery {
                path: &path,
                change_owner,
                change_revision,
                queries: 0,
            };
            let result = if reconcile {
                actuator
                    .reconcile_takeover_with_clock_v23(
                        &lease(),
                        locator(),
                        [33; 32],
                        &mut port,
                        10,
                        1100,
                        &mut || Ok(1200),
                    )
                    .map(|outcome| outcome.view)
            } else {
                actuator.observe_current_with_clock_v23(
                    &lease(),
                    locator(),
                    [33; 32],
                    &mut port,
                    10,
                    1100,
                    &mut || Ok(1200),
                )
            };
            assert_eq!(result, Err(Error::Conflict));
            assert_eq!(port.queries, 1);
            let after = actuator
                .view(locator())
                .expect("historical reads remain allowed");
            assert_eq!(after.revision, before.revision + u64::from(change_revision));
            assert_eq!(after.stage, before.stage);
            assert_eq!(after.finality, before.finality);
            if change_owner {
                assert_eq!(after, before);
            }
        }
    }
}
