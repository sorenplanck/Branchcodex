//! Filesystem/AEAD/MAC regressions only; fixtures are not economic authorities.
use super::*;

#[test]
fn local_read_never_creates_a_missing_scope_or_plan_and_domains_do_not_alias() {
    let directory = tempfile::tempdir().unwrap();
    let cache = SweepCache::open(directory.path()).unwrap();
    let nonce = [21; 32];
    let digest = [22; 32];
    let key = [23; 32];
    let auth = crate::auth::AuthKey::new([24; 32]).unwrap();
    assert!(cache.lookup_local_refund_v24(nonce).is_err());
    assert!(cache.begin_local_refund_read_v24(nonce, digest).is_err());
    assert!(
        !directory
            .path()
            .join("local-refund-build-proofs-v24")
            .exists()
    );
    let remote = cache.begin_build_v23(nonce, digest).unwrap();
    remote
        .store_plan(&key, b"remote-encrypted-plan-fixture")
        .unwrap();
    let local = cache.begin_local_refund_build_v24(nonce, digest).unwrap();
    assert!(local.load_plan(&key).unwrap().is_none());
    assert!(local.load_local_ready(b"scope", &auth).unwrap().is_none());
    local
        .store_plan(&key, b"local-encrypted-plan-fixture")
        .unwrap();
    drop(local);
    let read = cache.begin_local_refund_read_v24(nonce, digest).unwrap();
    assert_eq!(
        read.load_plan(&key).unwrap().unwrap().as_slice(),
        b"local-encrypted-plan-fixture"
    );
    assert!(
        read.load_public_local_ready_v24(b"scope", &auth)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        remote.load_plan(&key).unwrap().unwrap().as_slice(),
        b"remote-encrypted-plan-fixture"
    );
    drop(read);
    assert!(cache.begin_local_refund_read_v24(nonce, [24; 32]).is_err());
    assert!(cache.begin_local_refund_read_v24([25; 32], digest).is_err());
    assert!(
        !directory
            .path()
            .join("local-refund-build-proofs-v24")
            .join(format!("{}.lock", hex::encode([25; 32])))
            .exists()
    );
}

#[test]
fn local_issued_tombstone_without_ready_refuses_recreation_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let cache = SweepCache::open(directory.path()).unwrap();
    let nonce = [31; 32];
    let digest = [32; 32];
    let guard = cache.begin_local_refund_build_v24(nonce, digest).unwrap();
    guard
        .store_plan(&[33; 32], b"local-private-plan-fixture")
        .unwrap();
    let path = directory
        .path()
        .join("local-refund-build-proofs-v24")
        .join(format!("{}.issued", hex::encode(nonce)));
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&[34; 32]).unwrap();
    file.sync_all().unwrap();
    drop(guard);
    let read = cache.begin_local_refund_read_v24(nonce, digest).unwrap();
    assert!(
        read.load_public_local_ready_v24(b"scope", &crate::auth::AuthKey::new([33; 32]).unwrap())
            .is_err()
    );
}

fn local_ready_fixture(
    nonce: [u8; 32],
    digest: [u8; 32],
) -> xmr_key_image_proof::LocalRefundBuildResponseV24<BuildSweepResponseV2> {
    use xmr_key_image_proof::*;
    let request = LocalRefundLoadRequestV24 {
        api_version: 24,
        request_nonce: nonce,
        network_genesis: [1; 32],
        route: [2; 32],
        session: [3; 32],
        terms: [4; 32],
        effect_id: nonce,
        fencing_epoch: 1,
        semantic_digest: [6; 32],
        dom_refund_tx_hash: [8; 32],
        graph_digest: [9; 32],
        settlement_id: [10; 32],
        funding_tx_hash: [11; 32],
        funded_amount: 1000,
        destination: "cache-only-fixture-not-an-operational-address".into(),
        expected_spend_public_key: [12; 32],
        max_fee: 20,
        auth_tag: [0; 32],
    };
    let context = InputSpendContextV23 {
        network_genesis: request.network_genesis,
        route: request.route,
        session: request.session,
        terms: request.terms,
        funding_tx: request.funding_tx_hash,
        output_index: 0,
        sweep_tx: [13; 32],
        destination: destination_digest_v23(&request.destination),
        funded_amount: 1000,
        fee: 10,
        action: InputSpendActionV23::Refund,
    };
    // Canonically encoded public points/scalar, solely a framing fixture.
    // No proof equation or raw transaction validity is asserted by this test.
    let basepoint = monero_wallet_ng::util::public_key(
        &crate::parse_scalar({
            let mut s = [0; 32];
            s[0] = 1;
            s
        })
        .unwrap(),
    )
    .compress()
    .to_bytes();
    let mut input_proof = Vec::new();
    input_proof.extend_from_slice(&basepoint);
    input_proof.extend_from_slice(&basepoint);
    input_proof.extend_from_slice(&[0; 32]);
    let mut payout = Vec::new();
    payout.extend_from_slice(&basepoint);
    payout.extend_from_slice(&basepoint);
    payout.extend_from_slice(&input_proof);
    LocalRefundBuildResponseV24 {
        api_version: 24,
        cache_request_hash: digest,
        public_scope: LocalRefundReadyScopeV24 {
            request,
            local_authorization_digest: [7; 32],
            output_index: 0,
            funding_height: 100,
        },
        local_authorization_digest: [7; 32],
        effect_id: nonce,
        fencing_epoch: 1,
        semantic_digest: [6; 32],
        dom_refund_tx_hash: [8; 32],
        graph_digest: [9; 32],
        sweep: BuildSweepResponseV2 {
            api_version: 2,
            request_nonce: nonce,
            tx_hash: context.sweep_tx,
            raw_tx: vec![1, 2, 3],
        },
        context: context.canonical_bytes().unwrap(),
        input_proof,
        tx_key_proofs: vec![payout],
        ring_members: (0..16)
            .map(|global_index| BuiltRingMemberV23 {
                global_index,
                key: basepoint,
                commitment: basepoint,
            })
            .collect(),
    }
}

#[test]
fn public_ready_read_survives_private_plan_retirement_and_scope_or_payload_mutation_fails() {
    let directory = tempfile::tempdir().unwrap();
    let cache = SweepCache::open(directory.path()).unwrap();
    let nonce = [41; 32];
    let digest = [42; 32];
    let auth = crate::auth::AuthKey::new([43; 32]).unwrap();
    let response = local_ready_fixture(nonce, digest);
    let scope = response
        .public_scope
        .request
        .canonical_auth_bytes()
        .unwrap();
    let guard = cache.begin_local_refund_build_v24(nonce, digest).unwrap();
    guard
        .store_plan(
            &[44; 32],
            b"unparseable private fixture; never opened by LOAD",
        )
        .unwrap();
    guard.store_local_ready(&response, &scope, &auth).unwrap();
    drop(guard);
    let path = directory.path().join("local-refund-build-proofs-v24");
    let stem = hex::encode(nonce);
    fs::remove_file(path.join(format!("{stem}.plan"))).unwrap();
    // Reopen the cache owner, not merely its per-request guard. No private
    // plan or in-memory result from BUILD may be needed to read durable Ready.
    drop(cache);
    let cache = SweepCache::open(directory.path()).unwrap();
    let auth = crate::auth::AuthKey::new([43; 32]).unwrap();
    let inventory = || {
        fs::read_dir(&path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let before_load = inventory();
    let guard = cache.lookup_local_refund_v24(nonce).unwrap();
    assert_eq!(guard.request_hash_v24(), digest);
    assert_eq!(
        guard.load_public_local_ready_v24(&scope, &auth).unwrap(),
        Some(response)
    );
    assert_eq!(
        inventory(),
        before_load,
        "public LOAD must not rewrite durable artifacts"
    );
    assert!(
        guard
            .load_public_local_ready_v24(&scope, &crate::auth::AuthKey::new([45; 32]).unwrap())
            .is_err()
    );
    let mut changed_scope = scope.clone();
    changed_scope[50] ^= 1;
    assert!(
        guard
            .load_public_local_ready_v24(&changed_scope, &auth)
            .is_err()
    );
    let ready_path = path.join(format!("{stem}.ready"));
    let issued_path = path.join(format!("{stem}.issued"));
    let original = fs::read(&ready_path).unwrap();
    // An attacker can replace the unauthenticated issued SHA alongside JSON,
    // but cannot transplant any part of a MAC-bound result or origin.
    for field in ["payload", "scope", "hash", "origin", "height", "index"] {
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        match field {
            "payload" => value["response"]["sweep"]["raw_tx"][0] = 99.into(),
            "scope" => value["scope"][0] = 99.into(),
            "hash" => value["response"]["cache_request_hash"][0] = 99.into(),
            "origin" => value["response"]["local_authorization_digest"][0] = 99.into(),
            "height" => value["response"]["public_scope"]["funding_height"] = 101.into(),
            "index" => value["response"]["public_scope"]["output_index"] = 1.into(),
            _ => unreachable!(),
        }
        let changed = serde_json::to_vec(&value).unwrap();
        fs::write(&ready_path, &changed).unwrap();
        fs::write(&issued_path, SweepCache::request_hash(&changed)).unwrap();
        assert!(
            guard.load_public_local_ready_v24(&scope, &auth).is_err(),
            "{field}"
        );
    }
    fs::write(&ready_path, &original).unwrap();
    fs::write(&issued_path, SweepCache::request_hash(&original)).unwrap();
    assert!(
        guard
            .load_public_local_ready_v24(&scope, &auth)
            .unwrap()
            .is_some()
    );
    fs::remove_file(&issued_path).unwrap();
    assert!(matches!(
        guard.load_public_local_ready_v24(&scope, &auth),
        Err(CacheError::Unavailable)
    ));
    assert!(
        !issued_path.exists(),
        "LOAD must not finish a crashed build publication"
    );
    assert!(!path.join(format!("{stem}.plan")).exists());
}

#[test]
fn encrypted_plan_roundtrip_and_wrong_key_or_request_are_closed() {
    let directory = tempfile::tempdir().unwrap();
    let cache = SweepCache::open(directory.path()).unwrap();
    let nonce = [1; 32];
    let digest = [2; 32];
    let key = [3; 32];
    let guard = cache.begin_build_v23(nonce, digest).unwrap();
    let plaintext = b"test-only AEAD payload; not a signing plan";
    guard.store_plan(&key, plaintext).unwrap();
    assert_eq!(
        guard.load_plan(&key).unwrap().unwrap().as_slice(),
        plaintext
    );
    assert!(guard.load_plan(&[4; 32]).is_err());
    assert!(guard.store_plan(&key, plaintext).is_err());
    drop(guard);
    assert!(cache.begin_build_v23(nonce, [5; 32]).is_err());
    let reopened = cache.begin_build_v23(nonce, digest).unwrap();
    assert_eq!(
        reopened.load_plan(&key).unwrap().unwrap().as_slice(),
        plaintext
    );
}

#[test]
fn request_lock_prevents_concurrent_new_plan_and_plan_links_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let cache = SweepCache::open(directory.path()).unwrap();
    let nonce = [6; 32];
    let digest = [7; 32];
    let key = [8; 32];
    let guard = cache.begin_build_v23(nonce, digest).unwrap();
    assert!(cache.begin_build_v23(nonce, digest).is_err());
    guard.store_plan(&key, b"test-only plaintext").unwrap();
    let path = directory
        .path()
        .join("build-proofs-v23")
        .join(format!("{}.plan", hex::encode(nonce)));
    let extra = directory.path().join("unexpected-hardlink");
    fs::hard_link(&path, &extra).unwrap();
    assert!(guard.load_plan(&key).is_err());
}

#[test]
fn issued_tombstone_without_ready_is_corruption_not_recreation() {
    let directory = tempfile::tempdir().unwrap();
    let cache = SweepCache::open(directory.path()).unwrap();
    let nonce = [9; 32];
    let digest = [10; 32];
    let guard = cache.begin_build_v23(nonce, digest).unwrap();
    // Simulates loss of a public result after an issued marker. This marker is
    // deliberately invalid test state, not a fake proof or economic receipt.
    let path = directory
        .path()
        .join("build-proofs-v23")
        .join(format!("{}.issued", hex::encode(nonce)));
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&[11; 32]).unwrap();
    file.sync_all().unwrap();
    assert!(guard.load_ready().is_err());
}
