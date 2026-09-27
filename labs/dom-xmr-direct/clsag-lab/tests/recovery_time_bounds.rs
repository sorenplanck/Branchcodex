//! Conditional arithmetic only: none of these cost/delay assumptions is a
//! measured worst-case bound, a verified backend proof, or funding permission.
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use dom_core::{BlockHeight, Timestamp};
use dxp1_clsag_lab::xmr_recovery::{XmrDirectRecoveryLink, XmrRecoveryRoster};
use dxp1_clsag_lab::{
    recovery::RecoveryPlan,
    recovery_challenge::RecoveryChallenge,
    time_bounds::{
        AssumedClaimDelays, AssumedDirectRecoveryCosts, AssumedDomAnchor,
        AssumedPreparedRecoveryCosts, AssumedSerialRecoveryCosts, AssumedSessionRecoveryCosts,
        AssumedXmrRecoveryWindow, DomClockNetwork, InitialClaimOrder, TimingError,
    },
};
use frost::Participant;

#[test]
fn refuted_thirty_second_profile_admits_release_after_observed_recovery_is_possible() {
    // Arithmetic consequence of FAST-OPEN-AUDIT.md, not a funded attack:
    // OpenSSL recovered the original point in <8 seconds with the SAME 10M
    // steps. Eight seconds is an OBSERVED upper bound for that evaluator,
    // never a replacement minimum adversarial delay or admission policy.
    let roster =
        XmrRecoveryRoster::new([41; 32], [G * Scalar::from(17u64), G * Scalar::from(19u64)])
            .unwrap();
    let peer = Participant::new(2).unwrap();
    let link = XmrDirectRecoveryLink::new(
        &roster,
        peer,
        roster.recovery_domain(peer).unwrap(),
        roster.share_key(peer).unwrap(),
        [42; 32],
    )
    .unwrap();
    let costs = AssumedDirectRecoveryCosts {
        opening_and_check_secs: 60,
        overhead_secs: 5,
    };
    let old = AssumedXmrRecoveryWindow::from_direct_costs(
        &link,
        Timestamp(1000),
        30,
        Timestamp(1035),
        costs,
    )
    .unwrap();
    let competing = AssumedXmrRecoveryWindow::from_direct_costs(
        &link,
        Timestamp(1000),
        8,
        Timestamp(1035),
        costs,
    )
    .unwrap();
    assert!(competing.earliest_adversarial() < Timestamp(1010));
    for order in [InitialClaimOrder::XmrFirst, InitialClaimOrder::DomFirst] {
        assert_eq!(
            old.check_initial_claim_release(Timestamp(1010), order, DELAYS),
            Ok(())
        );
        assert_eq!(
            competing.check_initial_claim_release(Timestamp(1010), order, DELAYS),
            Err(TimingError::InitiationWindowExhausted)
        );
    }
    // Deferring the DOM refund does not repair early XMR recovery. The old
    // fixture even admits an offers-ready deadline long AFTER this evaluator
    // has finished. A known-false premise cannot authorize funding/release.
    let anchor = AssumedDomAnchor::new(BlockHeight(10), Timestamp(1000));
    assert!(old
        .required_dom_refund_height(
            &anchor,
            DomClockNetwork::Regtest,
            0,
            Timestamp(1028),
            DELAYS
        )
        .is_ok());
    assert_eq!(
        competing.required_dom_refund_height(
            &anchor,
            DomClockNetwork::Regtest,
            0,
            Timestamp(1028),
            DELAYS
        ),
        Err(TimingError::InitiationWindowExhausted)
    );
}

#[test]
fn first_claim_release_rechecks_original_clock_and_entire_ordered_prefix() {
    let window = AssumedXmrRecoveryWindow::from_prepared_costs(
        &challenge(6),
        Timestamp(1000),
        20,
        Timestamp(1000),
        AssumedPreparedRecoveryCosts {
            solve_and_check_per_candidate_secs: 10,
            overhead_secs: 0,
        },
    )
    .unwrap();
    assert_eq!(
        window.check_initial_claim_release(Timestamp(1018), InitialClaimOrder::XmrFirst, DELAYS),
        Ok(())
    );
    assert_eq!(
        window.check_initial_claim_release(Timestamp(1016), InitialClaimOrder::DomFirst, DELAYS),
        Ok(())
    );
    for (order, boundary) in [
        (InitialClaimOrder::XmrFirst, 1019),
        (InitialClaimOrder::DomFirst, 1017),
    ] {
        for now in [boundary, 1020, 2000] {
            assert_eq!(
                window.check_initial_claim_release(Timestamp(now), order, DELAYS),
                Err(TimingError::InitiationWindowExhausted)
            );
        }
        assert_eq!(
            window.check_initial_claim_release(Timestamp(999), order, DELAYS),
            Err(TimingError::InvalidAssumption)
        );
        assert_eq!(
            window.check_initial_claim_release(Timestamp(u64::MAX), order, DELAYS),
            Err(TimingError::Overflow)
        );
    }
    let invalid = AssumedClaimDelays {
        xmr_resolution_secs: 0,
        ..DELAYS
    };
    assert_eq!(
        window.check_initial_claim_release(Timestamp(1000), InitialClaimOrder::XmrFirst, invalid),
        Err(TimingError::InvalidAssumption)
    );
    let overflow = AssumedClaimDelays {
        observation_secs: u64::MAX,
        ..DELAYS
    };
    assert_eq!(
        window.check_initial_claim_release(Timestamp(1000), InitialClaimOrder::DomFirst, overflow),
        Err(TimingError::Overflow)
    );
}

#[test]
fn dom_first_requires_the_entire_observation_and_two_claim_prefix_before_recovery() {
    let window = AssumedXmrRecoveryWindow::from_prepared_costs(
        &challenge(6),
        Timestamp(1000),
        20,
        Timestamp(1000),
        AssumedPreparedRecoveryCosts {
            solve_and_check_per_candidate_secs: 10,
            overhead_secs: 0,
        },
    )
    .unwrap();
    let anchor = AssumedDomAnchor::new(BlockHeight(10), Timestamp(1000));
    let xmr_first = window
        .required_dom_refund_height(
            &anchor,
            DomClockNetwork::Regtest,
            0,
            Timestamp(1018),
            DELAYS,
        )
        .unwrap();
    assert_eq!(
        window.required_dom_refund_height_for_dom_first(
            &anchor,
            DomClockNetwork::Regtest,
            0,
            Timestamp(1018),
            DELAYS
        ),
        Err(TimingError::InitiationWindowExhausted)
    );
    assert_eq!(
        window.required_dom_refund_height_for_dom_first(
            &anchor,
            DomClockNetwork::Regtest,
            0,
            Timestamp(1017),
            DELAYS
        ),
        Err(TimingError::InitiationWindowExhausted)
    );
    assert_eq!(
        window.required_dom_refund_height_for_dom_first(
            &anchor,
            DomClockNetwork::Regtest,
            0,
            Timestamp(1016),
            DELAYS
        ),
        Ok(xmr_first)
    );
    assert_eq!(
        window.required_dom_refund_height_for_dom_first(
            &anchor,
            DomClockNetwork::Regtest,
            0,
            Timestamp(999),
            DELAYS
        ),
        Err(TimingError::InvalidAssumption)
    );
    assert_eq!(
        window.required_dom_refund_height_for_dom_first(
            &anchor,
            DomClockNetwork::Regtest,
            0,
            Timestamp(u64::MAX - 1),
            DELAYS
        ),
        Err(TimingError::Overflow)
    );
    assert_eq!(
        window.required_dom_refund_height_for_dom_first(
            &anchor,
            DomClockNetwork::Regtest,
            0,
            Timestamp(1000),
            AssumedClaimDelays {
                observation_secs: u64::MAX,
                ..DELAYS
            }
        ),
        Err(TimingError::Overflow)
    );
    assert_eq!(
        window.required_dom_refund_height_for_dom_first(
            &anchor,
            DomClockNetwork::Regtest,
            0,
            Timestamp(1000),
            AssumedClaimDelays {
                dom_resolution_secs: 0,
                ..DELAYS
            }
        ),
        Err(TimingError::InvalidAssumption)
    );
}

#[test]
fn direct_budget_is_one_opening_bound_to_its_roster_capsule_and_original_clock() {
    let roster =
        XmrRecoveryRoster::new([41; 32], [G * Scalar::from(17u64), G * Scalar::from(19u64)])
            .unwrap();
    let id = Participant::new(2).unwrap();
    let link = XmrDirectRecoveryLink::new(
        &roster,
        id,
        roster.recovery_domain(id).unwrap(),
        roster.share_key(id).unwrap(),
        [42; 32],
    )
    .unwrap();
    let costs = AssumedDirectRecoveryCosts {
        opening_and_check_secs: 20,
        overhead_secs: 3,
    };
    let window = AssumedXmrRecoveryWindow::from_direct_costs(
        &link,
        Timestamp(1000),
        20,
        Timestamp(1005),
        costs,
    )
    .unwrap();
    assert_eq!(window.candidates(), 1);
    assert_eq!(window.capsule_binding(), link.binding());
    assert_eq!(window.earliest_adversarial(), Timestamp(1020));
    assert_eq!(window.latest_honest(), Timestamp(1028));
    let anchor = AssumedDomAnchor::new(BlockHeight(10), Timestamp(1000));
    let height = window
        .required_dom_refund_height(
            &anchor,
            DomClockNetwork::Mainnet,
            0,
            Timestamp(1018),
            DELAYS,
        )
        .unwrap();
    assert_eq!(
        anchor.earliest_refund_time(height, DomClockNetwork::Mainnet, 0),
        Ok(Timestamp(1032))
    );
    assert_eq!(
        window.required_dom_refund_height(
            &anchor,
            DomClockNetwork::Mainnet,
            0,
            Timestamp(1019),
            DELAYS
        ),
        Err(TimingError::InitiationWindowExhausted)
    );
    let legacy = AssumedXmrRecoveryWindow::from_prepared_costs(
        &challenge(198),
        Timestamp(1000),
        20,
        Timestamp(1005),
        AssumedPreparedRecoveryCosts {
            solve_and_check_per_candidate_secs: 1,
            overhead_secs: 3,
        },
    )
    .unwrap();
    assert_eq!(legacy.candidates(), 99);
    assert_eq!(legacy.latest_honest(), Timestamp(1107));
    assert_ne!(window.capsule_binding(), legacy.capsule_binding());
    for invalid in [
        AssumedDirectRecoveryCosts {
            opening_and_check_secs: 0,
            ..costs
        },
        AssumedDirectRecoveryCosts {
            opening_and_check_secs: u64::MAX,
            ..costs
        },
        AssumedDirectRecoveryCosts {
            overhead_secs: u64::MAX,
            ..costs
        },
    ] {
        assert!(AssumedXmrRecoveryWindow::from_direct_costs(
            &link,
            Timestamp(1000),
            20,
            Timestamp(1005),
            invalid
        )
        .is_err());
    }
    assert!(matches!(
        AssumedXmrRecoveryWindow::from_direct_costs(
            &link,
            Timestamp(1000),
            20,
            Timestamp(999),
            costs
        ),
        Err(TimingError::InvalidAssumption)
    ));
    assert!(matches!(
        AssumedXmrRecoveryWindow::from_direct_costs(
            &link,
            Timestamp(u64::MAX),
            20,
            Timestamp(u64::MAX),
            costs
        ),
        Err(TimingError::Overflow)
    ));
}

fn challenge(n: u16) -> RecoveryChallenge {
    let commitments = (1..=n / 2 + 1)
        .map(|i| G * Scalar::from(u64::from(i)))
        .collect();
    let plan = RecoveryPlan::from_commitments([32; 32], n / 2 + 1, n, commitments).unwrap();
    RecoveryChallenge::derive(
        &plan,
        b"fixture setup",
        &vec![vec![1]; usize::from(n)],
        b"fixture proof",
    )
    .unwrap()
}

const COSTS: AssumedSerialRecoveryCosts = AssumedSerialRecoveryCosts {
    verification_per_candidate_secs: 1,
    solve_per_candidate_secs: 1,
    overhead_secs: 1,
};
const DELAYS: AssumedClaimDelays = AssumedClaimDelays {
    xmr_resolution_secs: 1,
    observation_secs: 1,
    dom_resolution_secs: 1,
};

#[test]
fn prepared_session_keeps_full_search_and_original_disclosure_clock() {
    let challenge = challenge(198);
    let costs = AssumedPreparedRecoveryCosts {
        solve_and_check_per_candidate_secs: 1,
        overhead_secs: 3,
    };
    let window = AssumedXmrRecoveryWindow::from_prepared_costs(
        &challenge,
        Timestamp(1000),
        2,
        Timestamp(1000),
        costs,
    )
    .unwrap();
    assert_eq!(window.candidates(), 99);
    assert_eq!(window.capsule_binding(), challenge.binding());
    assert_eq!(window.earliest_adversarial(), Timestamp(1002));
    assert_eq!(window.latest_honest(), Timestamp(1102));
    let anchor = AssumedDomAnchor::new(BlockHeight(10), Timestamp(1000));
    assert_eq!(
        window.required_dom_refund_height(
            &anchor,
            DomClockNetwork::Mainnet,
            0,
            Timestamp(1001),
            DELAYS,
        ),
        Err(TimingError::InitiationWindowExhausted)
    );
    let height = window
        .required_dom_refund_height(
            &anchor,
            DomClockNetwork::Mainnet,
            0,
            Timestamp(1000),
            DELAYS,
        )
        .unwrap();
    assert_eq!(
        anchor.earliest_refund_time(height, DomClockNetwork::Mainnet, 0),
        Ok(Timestamp(1106))
    );
    for invalid in [
        AssumedPreparedRecoveryCosts {
            solve_and_check_per_candidate_secs: 0,
            ..costs
        },
        AssumedPreparedRecoveryCosts {
            solve_and_check_per_candidate_secs: u64::MAX,
            ..costs
        },
        AssumedPreparedRecoveryCosts {
            overhead_secs: u64::MAX,
            ..costs
        },
    ] {
        assert!(AssumedXmrRecoveryWindow::from_prepared_costs(
            &challenge,
            Timestamp(1000),
            2,
            Timestamp(1000),
            invalid,
        )
        .is_err());
    }
}

#[test]
fn session_saves_only_repeated_public_verification_never_candidate_checks() {
    for n in [6, 198, 512] {
        let challenge = challenge(n);
        let session = AssumedXmrRecoveryWindow::from_session_costs(
            &challenge,
            Timestamp(1000),
            2,
            Timestamp(1000),
            AssumedSessionRecoveryCosts {
                public_verification_once_secs: 2,
                solve_and_check_per_candidate_secs: 1,
                overhead_secs: 1,
            },
        )
        .unwrap();
        let historical = AssumedXmrRecoveryWindow::from_serial_costs(
            &challenge,
            Timestamp(1000),
            2,
            Timestamp(1000),
            AssumedSerialRecoveryCosts {
                verification_per_candidate_secs: 2,
                ..COSTS
            },
        )
        .unwrap();
        assert_eq!(session.candidates(), n / 2);
        assert_eq!(session.capsule_binding(), challenge.binding());
        assert_eq!(session.latest_honest(), Timestamp(1003 + u64::from(n / 2)));
        assert_eq!(
            historical.latest_honest().0 - session.latest_honest().0,
            2 * u64::from(n / 2 - 1)
        );
        let anchor = AssumedDomAnchor::new(BlockHeight(10), Timestamp(1000));
        let height = session
            .required_dom_refund_height(
                &anchor,
                DomClockNetwork::Mainnet,
                0,
                Timestamp(1000),
                DELAYS,
            )
            .unwrap();
        assert_eq!(
            anchor
                .earliest_refund_time(height, DomClockNetwork::Mainnet, 0)
                .unwrap()
                .0,
            session.latest_honest().0 + 4
        );
    }
}

#[test]
fn session_costs_reject_zero_work_and_overflow() {
    let challenge = challenge(198);
    for costs in [
        AssumedSessionRecoveryCosts {
            public_verification_once_secs: 0,
            solve_and_check_per_candidate_secs: 1,
            overhead_secs: 0,
        },
        AssumedSessionRecoveryCosts {
            public_verification_once_secs: 1,
            solve_and_check_per_candidate_secs: 0,
            overhead_secs: 0,
        },
        AssumedSessionRecoveryCosts {
            public_verification_once_secs: u64::MAX,
            solve_and_check_per_candidate_secs: 1,
            overhead_secs: 0,
        },
        AssumedSessionRecoveryCosts {
            public_verification_once_secs: 1,
            solve_and_check_per_candidate_secs: u64::MAX,
            overhead_secs: 0,
        },
        AssumedSessionRecoveryCosts {
            public_verification_once_secs: 1,
            solve_and_check_per_candidate_secs: 1,
            overhead_secs: u64::MAX,
        },
    ] {
        assert!(AssumedXmrRecoveryWindow::from_session_costs(
            &challenge,
            Timestamp(0),
            1,
            Timestamp(0),
            costs
        )
        .is_err());
    }
}

#[test]
fn counts_every_candidate_and_retains_the_exact_capsule_binding() {
    for n in [6, 132, 166, 198, 512] {
        let challenge = challenge(n);
        let window = AssumedXmrRecoveryWindow::from_serial_costs(
            &challenge,
            Timestamp(1000),
            2,
            Timestamp(1003),
            COSTS,
        )
        .unwrap();
        assert_eq!(window.capsule_binding(), challenge.binding());
        assert_eq!(window.candidates(), n / 2);
        assert_eq!(window.earliest_adversarial(), Timestamp(1002));
        assert_eq!(window.latest_honest(), Timestamp(1004 + u64::from(n)));
    }
}

#[test]
fn full_search_cost_increases_the_native_refund_height_and_keeps_strict_margin() {
    let anchor = AssumedDomAnchor::new(BlockHeight(10), Timestamp(1000));
    let window = AssumedXmrRecoveryWindow::from_serial_costs(
        &challenge(6),
        Timestamp(1000),
        2,
        Timestamp(1000),
        COSTS,
    )
    .unwrap();
    let height = window
        .required_dom_refund_height(
            &anchor,
            DomClockNetwork::Mainnet,
            0,
            Timestamp(1000),
            DELAYS,
        )
        .unwrap();
    assert_eq!(window.latest_honest(), Timestamp(1007));
    assert_eq!(height, BlockHeight(141));
    assert_eq!(
        anchor.earliest_refund_time(height, DomClockNetwork::Mainnet, 0),
        Ok(Timestamp(1011))
    );
    assert_eq!(
        anchor.earliest_refund_time(BlockHeight(140), DomClockNetwork::Mainnet, 0),
        Ok(Timestamp(1010))
    );
    // Timing only a first success would choose H=137, permitting the DOM
    // refund before the assumed latest XMR recovery plus claim/race margins.
    let first_only = anchor
        .refund_height_strictly_after(Timestamp(1006), DomClockNetwork::Mainnet, 0)
        .unwrap();
    assert_eq!(first_only, BlockHeight(137));
    assert!(
        anchor
            .earliest_refund_time(first_only, DomClockNetwork::Mainnet, 0)
            .unwrap()
            .0
            < window.latest_honest().0 + 3
    );
}

#[test]
fn preparation_does_not_restart_the_public_capsule_clock() {
    let window = AssumedXmrRecoveryWindow::from_serial_costs(
        &challenge(6),
        Timestamp(1000),
        2,
        Timestamp(1000),
        COSTS,
    )
    .unwrap();
    let anchor = AssumedDomAnchor::new(BlockHeight(10), Timestamp(1000));
    for ready in [1001, 1002, 1100] {
        assert_eq!(
            window.required_dom_refund_height(
                &anchor,
                DomClockNetwork::Mainnet,
                0,
                Timestamp(ready),
                DELAYS,
            ),
            Err(TimingError::InitiationWindowExhausted)
        );
    }
    assert_eq!(
        window.required_dom_refund_height(
            &anchor,
            DomClockNetwork::Mainnet,
            0,
            Timestamp(999),
            DELAYS,
        ),
        Err(TimingError::InvalidAssumption)
    );
}

#[test]
fn impossible_assumptions_and_overflows_never_become_a_refund_height() {
    let challenge = challenge(6);
    let make = |disclosed, delay, starts, costs| {
        AssumedXmrRecoveryWindow::from_serial_costs(
            &challenge,
            Timestamp(disclosed),
            delay,
            Timestamp(starts),
            costs,
        )
    };
    assert!(matches!(
        make(1000, 2, 999, COSTS),
        Err(TimingError::InvalidAssumption)
    ));
    assert!(matches!(
        make(1000, 8, 1000, COSTS),
        Err(TimingError::InvalidAssumption)
    ));
    assert!(matches!(
        make(
            0,
            2,
            0,
            AssumedSerialRecoveryCosts {
                solve_per_candidate_secs: 0,
                ..COSTS
            }
        ),
        Err(TimingError::InvalidAssumption)
    ));
    assert!(matches!(
        make(u64::MAX, 1, u64::MAX, COSTS),
        Err(TimingError::Overflow)
    ));
    for costs in [
        AssumedSerialRecoveryCosts {
            verification_per_candidate_secs: u64::MAX,
            ..COSTS
        },
        AssumedSerialRecoveryCosts {
            solve_per_candidate_secs: u64::MAX / 2,
            ..COSTS
        },
        AssumedSerialRecoveryCosts {
            overhead_secs: u64::MAX,
            ..COSTS
        },
    ] {
        assert!(matches!(make(0, 2, 0, costs), Err(TimingError::Overflow)));
    }
    let window = make(0, 2, u64::MAX - 7, COSTS).unwrap();
    let anchor = AssumedDomAnchor::new(BlockHeight(0), Timestamp(0));
    assert_eq!(
        window.required_dom_refund_height(
            &anchor,
            DomClockNetwork::Mainnet,
            0,
            Timestamp(0),
            DELAYS
        ),
        Err(TimingError::Overflow)
    );
    assert_eq!(
        window.required_dom_refund_height(
            &anchor,
            DomClockNetwork::Mainnet,
            0,
            Timestamp(0),
            AssumedClaimDelays {
                dom_resolution_secs: 0,
                ..DELAYS
            }
        ),
        Err(TimingError::InvalidAssumption)
    );
}
