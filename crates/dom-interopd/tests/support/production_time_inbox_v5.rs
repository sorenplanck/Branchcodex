//! Exercises the actual persistence wrapper and signed durable time authority.
use super::*;
use production_time_inbox::{ProductionTimeEvidenceInboxV5, TIME_REFRESH_FILE_V5};
use std::{io::Write, sync::Arc};

fn inbox(directory: &TempDir) -> ProductionTimeEvidenceInboxV5 {
    ProductionTimeEvidenceInboxV5::new(Arc::new(cap_std::fs::Dir::from_std_file(
        fs::File::open(directory.path()).expect("retained state directory"),
    )))
}
fn publish(directory: &TempDir, bytes: &[u8]) {
    let stage = directory.path().join("refresh.new");
    let mut file = fs::File::create(&stage).expect("stage");
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).expect("owner only");
    file.write_all(bytes).expect("write");
    file.sync_all().expect("sync");
    fs::rename(stage, directory.path().join(TIME_REFRESH_FILE_V5)).expect("publish");
    fs::File::open(directory.path())
        .expect("directory")
        .sync_all()
        .expect("sync directory");
}

#[test]
fn live_refresh_v5_unlocks_new_funding_after_original_expiry_and_survives_restart() {
    let AdmittedHarness {
        _directory: _time_directory,
        time_path,
        time_config,
        time_store,
        admission,
        context,
        policy,
    } = admitted_harness_with_evidence_expiry(EVIDENCE_TIME + 15);
    let source_directory = owner_only_directory();
    let state = Rc::new(RefCell::new(BasePlanAuthorityState::default()));
    let mut persistence = adapter_from(time_store, &admission, &context, Rc::clone(&state))
        .with_evidence_inbox_v5(inbox(&source_directory));
    let (_coordinator_directory, coordinator_path) = coordinator_state_path();
    let mut coordinator = create_coordinator(&coordinator_path);
    let event = [0xd1; 32];
    let plan = plan_for_event(
        SettlementActionV1::Funding,
        LegIdV1::Upstream,
        1,
        event,
        0x71,
    );
    let now = EVIDENCE_TIME + 20;
    assert!(persistence
        .install_new_plan(&mut coordinator, plan.clone(), event, now * 1000)
        .is_err());
    assert_eq!(state.borrow().calls, 0);
    let refreshed = evidence(&policy, 2, now, 1);
    let signed = sign_new_evidence(&refreshed);
    publish(
        &source_directory,
        &signed.canonical_bytes().expect("canonical"),
    );
    persistence
        .install_new_plan(&mut coordinator, plan.clone(), event, now * 1000)
        .expect("fresh signed evidence consumed");
    assert_eq!(state.borrow().calls, 1);
    let stored = coordinator
        .load_plan_for_effect(plan.bindings().effect_id)
        .expect("retained plan");
    // Same snapshot replay is idempotent, with a new current proof.
    persistence
        .revalidate_preinstalled_new_plan(&stored, event, now * 1000)
        .expect("idempotent refresh");
    drop(persistence);
    fs::remove_file(source_directory.path().join(TIME_REFRESH_FILE_V5))
        .expect("remove transport copy");
    let time_store = DurableRouteTimeAnchorStoreV2::open_existing(&time_path, time_config)
        .expect("reopen time journal");
    let mut reopened = adapter_from(time_store, &admission, &context, Rc::clone(&state))
        .with_evidence_inbox_v5(inbox(&source_directory));
    reopened
        .revalidate_preinstalled_new_plan(&stored, event, (now + 1) * 1000)
        .expect("durable refresh survives missing feed");
    assert_eq!(state.borrow().calls, 1);
    if let Some(path) = std::env::var_os("DOM_INTEROP_V5_TIME_FIXTURE") {
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let value = serde_json::json!({"schema": "DOM-TIME-EVIDENCE-V5", "verification_time": now,
            "signed_hex": hex(&signed.canonical_bytes().expect("signed")),
            "pins": {"public_keys": context.evidence_authorities.xonly_keys().iter().map(|k| hex(k)).collect::<Vec<_>>(),
                "threshold": context.evidence_authorities.threshold(), "minimum_sequence": 2,
                "policy_digest": hex(&refreshed.policy_digest()), "route_scope_digest": hex(&refreshed.route_scope_digest())}});
        fs::write(path, serde_json::to_vec_pretty(&value).expect("fixture"))
            .expect("export public signed evidence");
    }
}

#[test]
fn malformed_refresh_v5_refuses_new_funding_but_does_not_gate_claim_or_refund() {
    let AdmittedHarness {
        _directory: _keep,
        time_store,
        admission,
        context,
        ..
    } = admitted_harness();
    let directory = owner_only_directory();
    publish(&directory, b"not signed time evidence");
    let state = Rc::new(RefCell::new(BasePlanAuthorityState::default()));
    let mut persistence = adapter_from(time_store, &admission, &context, Rc::clone(&state))
        .with_evidence_inbox_v5(inbox(&directory));
    let (_keep_coordinator, path) = coordinator_state_path();
    let mut coordinator = create_coordinator(&path);
    let now = EVIDENCE_TIME * 1000;
    let event = [0xd2; 32];
    assert!(persistence
        .install_new_plan(
            &mut coordinator,
            plan_for_event(
                SettlementActionV1::Funding,
                LegIdV1::Upstream,
                1,
                event,
                0x72
            ),
            event,
            now
        )
        .is_err());
    assert_eq!(state.borrow().calls, 0);
    for (action, tag) in [
        (SettlementActionV1::Claim, 0x73),
        (SettlementActionV1::Refund, 0x74),
    ] {
        let event = [tag; 32];
        persistence
            .install_new_plan(
                &mut coordinator,
                plan_for_event(action, LegIdV1::Downstream, 1, event, tag),
                event,
                now,
            )
            .expect("exit ignores transport failure");
    }
    assert_eq!(state.borrow().calls, 2);
}

#[test]
fn invalid_signature_v5_never_reaches_plan_authority_and_valid_replacement_recovers() {
    let AdmittedHarness {
        _directory: _keep,
        time_store,
        admission,
        context,
        policy,
        ..
    } = admitted_harness();
    let directory = owner_only_directory();
    let signed = sign_new_evidence(&evidence(&policy, 2, EVIDENCE_TIME + 1, 1));
    let mut broken = signed.canonical_bytes().expect("signed");
    *broken.last_mut().expect("signature") ^= 1;
    publish(&directory, &broken);
    let state = Rc::new(RefCell::new(BasePlanAuthorityState::default()));
    let mut persistence = adapter_from(time_store, &admission, &context, Rc::clone(&state))
        .with_evidence_inbox_v5(inbox(&directory));
    let (_keep_coordinator, path) = coordinator_state_path();
    let mut coordinator = create_coordinator(&path);
    let event = [0xd3; 32];
    let plan = plan_for_event(
        SettlementActionV1::Funding,
        LegIdV1::Downstream,
        1,
        event,
        0x75,
    );
    let now = (EVIDENCE_TIME + 1) * 1000;
    assert!(persistence
        .install_new_plan(&mut coordinator, plan.clone(), event, now)
        .is_err());
    assert_eq!(state.borrow().calls, 0);
    publish(&directory, &signed.canonical_bytes().expect("signed"));
    persistence
        .install_new_plan(&mut coordinator, plan, event, now)
        .expect("valid replacement");
    assert_eq!(state.borrow().calls, 1);
}

#[test]
fn inbox_v5_rejects_aliases_permissions_directories_and_bounded_corruption() {
    use std::os::unix::fs::symlink;
    let directory = owner_only_directory();
    let reader = inbox(&directory);
    let path = directory.path().join(TIME_REFRESH_FILE_V5);
    assert!(reader.read_candidate().expect("missing").is_none());
    for bytes in [vec![], vec![1; 16_385], b"DOMRTSE2".to_vec()] {
        publish(&directory, &bytes);
        assert!(reader.read_candidate().is_err());
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("public mode");
    assert!(reader.read_candidate().is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
    let alias = directory.path().join("alias");
    fs::hard_link(&path, &alias).expect("alias");
    assert!(reader.read_candidate().is_err());
    fs::remove_file(&path).expect("remove");
    symlink(&alias, &path).expect("symlink");
    assert!(reader.read_candidate().is_err());
    fs::remove_file(&path).expect("remove");
    fs::create_dir(&path).expect("directory");
    assert!(reader.read_candidate().is_err());
    assert_eq!(
        format!("{reader:?}"),
        "ProductionTimeEvidenceInboxV5([redacted])"
    );
}

#[test]
fn signed_equivocation_v5_invalidates_durably_and_deleting_feed_cannot_restore_funding() {
    let AdmittedHarness {
        _directory: _keep,
        time_path,
        time_config,
        time_store,
        admission,
        context,
        policy,
    } = admitted_harness();
    let directory = owner_only_directory();
    // Same sequence as the frozen evidence, with different signed facts.
    let conflict = sign_new_evidence(&evidence(&policy, 1, EVIDENCE_TIME + 1, 1));
    publish(
        &directory,
        &conflict.canonical_bytes().expect("signed conflict"),
    );
    let state = Rc::new(RefCell::new(BasePlanAuthorityState::default()));
    let mut persistence = adapter_from(time_store, &admission, &context, Rc::clone(&state))
        .with_evidence_inbox_v5(inbox(&directory));
    let (_keep_coordinator, path) = coordinator_state_path();
    let mut coordinator = create_coordinator(&path);
    let event = [0xd4; 32];
    let plan = plan_for_event(
        SettlementActionV1::Funding,
        LegIdV1::Upstream,
        1,
        event,
        0x76,
    );
    let now = (EVIDENCE_TIME + 1) * 1000;
    assert!(persistence
        .install_new_plan(&mut coordinator, plan.clone(), event, now)
        .is_err());
    assert_eq!(state.borrow().calls, 0);
    drop(persistence);
    fs::remove_file(directory.path().join(TIME_REFRESH_FILE_V5))
        .expect("remove conflicting transport");
    let store = DurableRouteTimeAnchorStoreV2::open_existing(&time_path, time_config)
        .expect("reopen invalidated authority");
    let mut reopened = adapter_from(store, &admission, &context, Rc::clone(&state))
        .with_evidence_inbox_v5(inbox(&directory));
    assert!(reopened
        .install_new_plan(&mut coordinator, plan, event, now)
        .is_err());
    assert_eq!(state.borrow().calls, 0);
    let event = [0xd5; 32];
    reopened
        .install_new_plan(
            &mut coordinator,
            plan_for_event(
                SettlementActionV1::Refund,
                LegIdV1::Upstream,
                1,
                event,
                0x77,
            ),
            event,
            now,
        )
        .expect("refund remains an exit");
}
