//! Enrollment storage regressions using the existing real DLEQ fixture. The
//! legacy policy fixture is deliberately never passed to the enrollment API.
use super::*;
use xmr_session_init::{
    initialize_enrolled_session_for_role_v23, prepare_xmr_share_enrollment_v23,
    resume_enrolled_session_for_role_v23,
};

#[derive(Default)]
struct CountedRng {
    bytes: usize,
}
impl rand::RngCore for CountedRng {
    fn next_u32(&mut self) -> u32 {
        self.bytes += 4;
        rand::RngCore::next_u32(&mut rand::thread_rng())
    }
    fn next_u64(&mut self) -> u64 {
        self.bytes += 8;
        rand::RngCore::next_u64(&mut rand::thread_rng())
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.bytes += bytes.len();
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), bytes);
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl rand::CryptoRng for CountedRng {}

#[test]
fn enrolled_custody_replays_without_nonce_and_never_repairs_partial_pairs() {
    let f = fixture();
    let enrollment = prepare_xmr_share_enrollment_v23(&f.setup, &f.refund).unwrap();
    enrollment.require_setup(&f.setup, &f.refund).unwrap();
    let root = tempfile::tempdir().unwrap();
    let store = EncryptedSqliteSecretStore::open(
        &root.path().join("secrets.sqlite"),
        SecretStoreMasterKey::new([31; 32]).unwrap(),
    )
    .unwrap();
    let nullifiers = DleqNullifierStore::open(&root.path().join("nullifiers.sqlite")).unwrap();
    let mut rng = CountedRng::default();
    let role = XmrLocalShareRoleV11::ClaimReceiver;
    assert!(initialize_enrolled_session_for_role_v23(
        &enrollment,
        &store,
        &nullifiers,
        local(role, 7),
        &mut rng,
    )
    .is_err());
    assert_eq!(rng.bytes, 0);
    assert!(matches!(
        store.load(&f.setup.settlement_id(), &f.setup.terms_hash()),
        Err(SecretStoreError::NotFound)
    ));
    assert!(matches!(
        nullifiers.require_registered(
            f.setup.settlement_id(),
            f.setup.binding_hash(),
            &f.setup.claim()
        ),
        Err(NullifierError::NotFound)
    ));

    let first = initialize_enrolled_session_for_role_v23(
        &enrollment,
        &store,
        &nullifiers,
        local(role, 11),
        &mut rng,
    )
    .unwrap();
    assert_eq!(first.nullifier, RegistrationOutcome::Inserted);
    let prior = rng.bytes;
    assert!(prior > 0);
    assert_eq!(
        initialize_enrolled_session_for_role_v23(
            &enrollment,
            &store,
            &nullifiers,
            local(role, 11),
            &mut rng,
        )
        .unwrap()
        .nullifier,
        RegistrationOutcome::Idempotent
    );
    assert_eq!(rng.bytes, prior);
    drop(store);
    drop(nullifiers);
    let store = EncryptedSqliteSecretStore::open_existing(
        &root.path().join("secrets.sqlite"),
        SecretStoreMasterKey::new([31; 32]).unwrap(),
    )
    .unwrap();
    let nullifiers =
        DleqNullifierStore::open_existing(&root.path().join("nullifiers.sqlite")).unwrap();
    resume_enrolled_session_for_role_v23(&enrollment, &store, &nullifiers, role).unwrap();
    assert!(resume_enrolled_session_for_role_v23(
        &enrollment,
        &store,
        &nullifiers,
        XmrLocalShareRoleV11::RefundReceiver,
    )
    .is_err());

    // Deliberately incomplete registrations are made by the real API, not
    // raw SQLite editing. Enrollment does not repair this crash cut.
    let partial_store = EncryptedSqliteSecretStore::open(
        &root.path().join("partial-secrets.sqlite"),
        SecretStoreMasterKey::new([32; 32]).unwrap(),
    )
    .unwrap();
    let partial_nullifiers =
        DleqNullifierStore::open(&root.path().join("partial-nullifiers.sqlite")).unwrap();
    partial_nullifiers
        .register(
            f.setup.settlement_id(),
            f.setup.binding_hash(),
            &f.setup.claim(),
        )
        .unwrap();
    assert!(initialize_enrolled_session_for_role_v23(
        &enrollment,
        &partial_store,
        &partial_nullifiers,
        local(role, 11),
        &mut rng,
    )
    .is_err());
    assert_eq!(rng.bytes, prior);
    assert!(matches!(
        partial_store.load(&f.setup.settlement_id(), &f.setup.terms_hash()),
        Err(SecretStoreError::NotFound)
    ));

    let missing_nullifiers =
        DleqNullifierStore::open(&root.path().join("missing-nullifiers.sqlite")).unwrap();
    assert!(initialize_enrolled_session_for_role_v23(
        &enrollment,
        &store,
        &missing_nullifiers,
        local(role, 11),
        &mut rng,
    )
    .is_err());
    assert_eq!(rng.bytes, prior);
    assert!(matches!(
        missing_nullifiers.require_registered(
            f.setup.settlement_id(),
            f.setup.binding_hash(),
            &f.setup.claim()
        ),
        Err(NullifierError::NotFound)
    ));
}
