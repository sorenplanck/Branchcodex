#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use dom_core::Timestamp;
use dxp1_clsag_lab::{
    release_journal::{
        claim_digest, InitialClaimJournal, JournalError, ReleasePolicy, ReleaseState,
    },
    time_bounds::{
        AssumedClaimDelays, AssumedDirectRecoveryCosts, AssumedXmrRecoveryWindow,
        InitialClaimOrder, TimingError,
    },
    xmr_recovery::{XmrDirectRecoveryLink, XmrRecoveryRoster},
};
use frost::Participant;

const PAYLOAD: &[u8] = b"private completed initial claim fixture; never persisted";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "release-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }
    fn path(&self) -> PathBuf {
        self.0.join("initial.wal")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn policy(disclosed: u64, order: InitialClaimOrder, operation: u8) -> ReleasePolicy {
    let roster =
        XmrRecoveryRoster::new([3; 32], [Scalar::from(7u64) * G, Scalar::from(11u64) * G]).unwrap();
    let role = Participant::new(2).unwrap();
    let link = XmrDirectRecoveryLink::new(
        &roster,
        role,
        roster.recovery_domain(role).unwrap(),
        roster.share_key(role).unwrap(),
        [9; 32],
    )
    .unwrap();
    let window = AssumedXmrRecoveryWindow::from_direct_costs(
        &link,
        Timestamp(disclosed),
        30,
        Timestamp(disclosed + 35),
        AssumedDirectRecoveryCosts {
            opening_and_check_secs: 60,
            overhead_secs: 5,
        },
    )
    .unwrap();
    ReleasePolicy::new(
        [operation; 32],
        &window,
        order,
        AssumedClaimDelays {
            xmr_resolution_secs: 1,
            observation_secs: 1,
            dom_resolution_secs: 1,
        },
        claim_digest(PAYLOAD),
    )
    .unwrap()
}
fn original() -> ReleasePolicy {
    policy(1000, InitialClaimOrder::XmrFirst, 5)
}
fn now() -> Timestamp {
    Timestamp(1005)
}

#[tokio::test]
async fn private_restart_keeps_original_deadline_and_closes_late_initiation() {
    let scratch = Scratch::new();
    drop(InitialClaimJournal::create(&scratch.path(), original(), now()).unwrap());
    let mut journal = InitialClaimJournal::open(&scratch.path(), original()).unwrap();
    assert_eq!(journal.state().unwrap(), ReleaseState::Private);
    let result = journal
        .release_once(
            PAYLOAD,
            || Timestamp(1029),
            || async { panic!("late send") },
        )
        .await;
    assert!(matches!(
        result,
        Err(JournalError::Timing(TimingError::InitiationWindowExhausted))
    ));
    drop(journal);
    let mut reopened = InitialClaimJournal::open(&scratch.path(), original()).unwrap();
    assert_eq!(
        reopened.state().unwrap(),
        ReleaseState::InitialReleaseClosed
    );
    assert!(matches!(
        reopened
            .release_once(PAYLOAD, now, || async { panic!("clock rewind") })
            .await,
        Err(JournalError::InitialReleaseClosed)
    ));
}

#[tokio::test]
async fn rejected_rpc_is_possible_exposure_after_restart_and_cannot_retry() {
    let scratch = Scratch::new();
    let mut journal = InitialClaimJournal::create(&scratch.path(), original(), now()).unwrap();
    let result = journal
        .release_once(PAYLOAD, now, || async { Err::<(), _>("double spend") })
        .await
        .unwrap();
    assert_eq!(result, Err("double spend"));
    assert_eq!(journal.state().unwrap(), ReleaseState::ExposurePossible);
    drop(journal);
    let mut journal = InitialClaimJournal::open(&scratch.path(), original()).unwrap();
    for timestamp in [1005, 5000] {
        assert!(matches!(
            journal
                .release_once(
                    PAYLOAD,
                    || Timestamp(timestamp),
                    || async { panic!("retry") }
                )
                .await,
            Err(JournalError::NeedsReconciliation)
        ));
    }
}

#[tokio::test]
async fn storage_latency_and_clock_regression_prevent_the_network_call() {
    for timestamp in [1029, 1004] {
        let scratch = Scratch::new();
        let mut journal = InitialClaimJournal::create(&scratch.path(), original(), now()).unwrap();
        let mut clock = [1005, timestamp].into_iter();
        assert!(matches!(
            journal
                .release_once(
                    PAYLOAD,
                    || Timestamp(clock.next().unwrap()),
                    || async { panic!("time invalid after fsync") }
                )
                .await,
            Err(JournalError::Timing(_))
        ));
        drop(journal);
        assert_eq!(
            InitialClaimJournal::open(&scratch.path(), original())
                .unwrap()
                .state()
                .unwrap(),
            ReleaseState::ExposurePossible
        );
    }
}

#[tokio::test]
async fn clock_before_private_preparation_permanently_closes_initial_release() {
    let scratch = Scratch::new();
    let mut journal = InitialClaimJournal::create(&scratch.path(), original(), now()).unwrap();
    assert!(matches!(
        journal
            .release_once(PAYLOAD, || Timestamp(1004), || async { panic!("rollback") })
            .await,
        Err(JournalError::Timing(TimingError::InvalidAssumption))
    ));
    drop(journal);
    assert_eq!(
        InitialClaimJournal::open(&scratch.path(), original())
            .unwrap()
            .state()
            .unwrap(),
        ReleaseState::InitialReleaseClosed
    );
}

#[tokio::test]
async fn exact_transaction_required_and_dom_first_counts_counterpart_prefix() {
    let scratch = Scratch::new();
    let expected = policy(1000, InitialClaimOrder::DomFirst, 5);
    let mut journal = InitialClaimJournal::create(&scratch.path(), expected, now()).unwrap();
    let original_bytes = fs::read(scratch.path()).unwrap();
    assert!(matches!(
        journal
            .release_once(b"different claim", now, || async { panic!("wrong tx") })
            .await,
        Err(JournalError::PayloadMismatch)
    ));
    assert_eq!(fs::read(scratch.path()).unwrap(), original_bytes);
    assert!(matches!(
        journal
            .release_once(
                PAYLOAD,
                || Timestamp(1027),
                || async { panic!("DOM-first too late") }
            )
            .await,
        Err(JournalError::Timing(TimingError::InitiationWindowExhausted))
    ));
}

#[test]
fn immutable_bindings_creation_exclusion_and_file_lock() {
    let scratch = Scratch::new();
    let journal = InitialClaimJournal::create(&scratch.path(), original(), now()).unwrap();
    assert!(matches!(
        InitialClaimJournal::open(&scratch.path(), original()),
        Err(JournalError::Locked)
    ));
    assert!(InitialClaimJournal::create(&scratch.path(), original(), now()).is_err());
    drop(journal);
    let bytes = fs::read(scratch.path()).unwrap();
    for changed in [
        policy(1010, InitialClaimOrder::XmrFirst, 5),
        policy(1000, InitialClaimOrder::DomFirst, 5),
        policy(1000, InitialClaimOrder::XmrFirst, 6),
    ] {
        assert!(matches!(
            InitialClaimJournal::open(&scratch.path(), changed),
            Err(JournalError::BindingMismatch)
        ));
        assert_eq!(fs::read(scratch.path()).unwrap(), bytes);
    }
    assert_eq!(
        fs::metadata(scratch.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!bytes.windows(PAYLOAD.len()).any(|part| part == PAYLOAD));
}

#[tokio::test]
async fn every_torn_event_and_corrupted_byte_fail_closed_without_repair() {
    let source = Scratch::new();
    let mut journal = InitialClaimJournal::create(&source.path(), original(), now()).unwrap();
    let header_len = fs::metadata(source.path()).unwrap().len() as usize;
    journal
        .release_once(PAYLOAD, now, || async {})
        .await
        .unwrap();
    drop(journal);
    let bytes = fs::read(source.path()).unwrap();
    let damaged = Scratch::new();
    // An exact valid header is a valid pre-exposure state. Removing an entire
    // synced event is backup/storage rollback, explicitly outside this model.
    for length in (0..header_len).chain(header_len + 1..bytes.len()) {
        fs::write(damaged.path(), &bytes[..length]).unwrap();
        assert!(
            InitialClaimJournal::open(&damaged.path(), original()).is_err(),
            "length {length}"
        );
        assert_eq!(fs::metadata(damaged.path()).unwrap().len(), length as u64);
    }
    for index in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[index] ^= 1;
        fs::write(damaged.path(), &bad).unwrap();
        assert!(
            InitialClaimJournal::open(&damaged.path(), original()).is_err(),
            "byte {index}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    fs::write(damaged.path(), trailing).unwrap();
    assert!(InitialClaimJournal::open(&damaged.path(), original()).is_err());
}

#[test]
fn missing_record_cannot_be_opened_or_silently_recreated() {
    let scratch = Scratch::new();
    assert!(matches!(
        InitialClaimJournal::open(&scratch.path(), original()),
        Err(JournalError::Io(_))
    ));
    assert!(!scratch.path().exists());
}

#[tokio::test]
async fn cancellation_while_rpc_is_pending_keeps_exposure_after_reopen() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let scratch = Scratch::new();
    let mut journal = InitialClaimJournal::create(&scratch.path(), original(), now()).unwrap();
    let mut send = Box::pin(journal.release_once(PAYLOAD, now, std::future::pending::<()>));
    assert!(matches!(
        send.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(send);
    drop(journal);
    let mut reopened = InitialClaimJournal::open(&scratch.path(), original()).unwrap();
    assert_eq!(reopened.state().unwrap(), ReleaseState::ExposurePossible);
    assert!(matches!(
        reopened
            .release_once(PAYLOAD, now, || async { panic!("cancel is not unsend") })
            .await,
        Err(JournalError::NeedsReconciliation)
    ));
}

#[test]
#[ignore = "only launched by process_exit_recovery with an owned path"]
fn crash_child() {
    let path = PathBuf::from(std::env::var_os("DXP1_RELEASE_TEST_PATH").unwrap());
    let phase = std::env::var("DXP1_RELEASE_TEST_PHASE").unwrap();
    if phase == "locked" {
        assert!(matches!(
            InitialClaimJournal::open(&path, original()),
            Err(JournalError::Locked)
        ));
        std::process::exit(74);
    }
    let mut journal = InitialClaimJournal::create(&path, original(), now()).unwrap();
    if phase == "private" {
        std::process::exit(73);
    }
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            journal
                .release_once(PAYLOAD, now, || async {
                    // Simulate abrupt process death after the durable exposure record,
                    // without completing a network request or running Rust destructors.
                    std::process::exit(73)
                })
                .await
                .unwrap();
        });
    panic!("child did not exit at intended cut");
}

#[tokio::test]
async fn process_exit_recovery_and_interprocess_exclusion() {
    for (phase, expected) in [
        ("private", ReleaseState::Private),
        ("exposed", ReleaseState::ExposurePossible),
    ] {
        let scratch = Scratch::new();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_child", "--ignored"])
            .env("DXP1_RELEASE_TEST_PATH", scratch.path())
            .env("DXP1_RELEASE_TEST_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        let mut journal = InitialClaimJournal::open(&scratch.path(), original()).unwrap();
        assert_eq!(journal.state().unwrap(), expected);
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_child", "--ignored"])
            .env("DXP1_RELEASE_TEST_PATH", scratch.path())
            .env("DXP1_RELEASE_TEST_PHASE", "locked")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(74));
        let result = journal
            .release_once(
                PAYLOAD,
                || Timestamp(5000),
                || async { panic!("unsafe resumed send") },
            )
            .await;
        if phase == "exposed" {
            assert!(matches!(result, Err(JournalError::NeedsReconciliation)));
        } else {
            assert!(matches!(
                result,
                Err(JournalError::Timing(TimingError::InitiationWindowExhausted))
            ));
        }
    }
}
