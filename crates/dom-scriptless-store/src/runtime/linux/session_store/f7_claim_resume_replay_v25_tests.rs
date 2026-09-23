//! Manual authentication benchmark on a private archived Store copy.
//! The synthetic timestamp below tests local authentication only: it is not
//! chain evidence and this test never signs, stages, or publishes a claim.
use super::*;

#[test]
#[ignore = "requires private archived claim copy in DOM_XMR_CLAIM_REPLAY_V25"]
fn archived_claim_publication_role_diagnosis() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(std::env::var("DOM_XMR_CLAIM_REPLAY_V25")?);
    let chain = TrustedChainIdV1::from_authenticated_genesis(
        dom_core::NETWORK_MAGIC_MAINNET,
        &dom_crypto::Hash256::from_bytes(dom_core::GENESIS_HASH_MAINNET),
    );
    let store = ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
        Arc::new(cap_std::fs::Dir::open_ambient_dir(
            &root,
            cap_std::ambient_authority(),
        )?),
        "contracts",
        BudgetPolicyV1::from_bytes(&std::fs::read(root.join("budget.bin"))?)?,
        chain,
    )?;
    let session = [0xd1; 32];
    let (gate, _, before) = store.authenticate_f7_claim_v12(session)?;
    let signer = store.authenticate_local_transport_signer_binding(session)?;
    let is_sender = signer.participant_id == gate.role.dom_claim_sender_id().0;
    let progress = store.f7_final_claim_progress_v14(chain, session);
    eprintln!("ARCHIVED_CLAIM_ROLE_V25 local_is_sender={is_sender} revision={} publication_progress={progress:?}", before.revision());
    if is_sender {
        assert!(progress.is_ok());
    } else {
        assert!(matches!(
            progress,
            Err(SessionStoreError::InvalidTransition)
        ));
    }
    let handle = store.f7_handle_v12(&gate);
    let state = store.f7_claim_receiver_state_v25(&handle, chain, signer.participant_id)?;
    assert!(matches!(
        (is_sender, state),
        (true, F7ClaimReceiverStateV25::Sender)
            | (false, F7ClaimReceiverStateV25::AwaitingObservation)
    ));
    let mut foreign = signer.participant_id;
    foreign[0] ^= 1;
    assert!(store
        .f7_claim_receiver_state_v25(&handle, chain, foreign)
        .is_err());
    let path = root
        .join("contracts/session-artifacts")
        .join(format!("{}.f7-v12-gate", hex_lower(&session)));
    let original = std::fs::read(&path)?;
    let mut corrupt = original.clone();
    *corrupt.last_mut().ok_or("empty gate")? ^= 1;
    std::fs::write(&path, corrupt)?;
    let rejected = store.f7_claim_receiver_state_v25(&handle, chain, signer.participant_id);
    std::fs::write(&path, original)?;
    assert!(rejected.is_err(), "corrupt gate became receiver wait");
    store.f7_claim_receiver_state_v25(&handle, chain, signer.participant_id)?;
    assert_eq!(before.as_bytes(), store.load_session(session)?.as_bytes());
    Ok(())
}

#[test]
#[ignore = "requires private archived claim copy in DOM_XMR_CLAIM_REPLAY_V25"]
fn archived_claim_resume_cost_and_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    use dom_adaptor::AcceptedSigningSessionV1;
    use std::time::{Duration, Instant};
    let root = std::path::PathBuf::from(std::env::var("DOM_XMR_CLAIM_REPLAY_V25")?);
    let chain = TrustedChainIdV1::from_authenticated_genesis(
        dom_core::NETWORK_MAGIC_MAINNET,
        &dom_crypto::Hash256::from_bytes(dom_core::GENESIS_HASH_MAINNET),
    );
    let budget = BudgetPolicyV1::from_bytes(&std::fs::read(root.join("budget.bin"))?)?;
    let store = ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
        Arc::new(cap_std::fs::Dir::open_ambient_dir(
            &root,
            cap_std::ambient_authority(),
        )?),
        "contracts",
        budget,
        chain,
    )?;
    let session = [0xd1; 32];
    let (_, issued, before) = store.authenticate_f7_claim_v12(session)?;
    let mut handle = ConsumedF7ClaimAuthorizationV12 {
        session_id: session,
        issuance_digest: issued.digest,
        consumption_digest: issued.consumption_digest,
        open_instance_id: store.open_instance_id,
        owner: store.reserve_claim_signing_process_owner_v2(issued.issuance_id)?,
        observed_at: std::cell::Cell::new(Instant::now()),
    };
    // Reproduce the former three-authentication path under one operation lock.
    let baseline_start = Instant::now();
    let baseline = {
        let _guard = store.operation_lock()?;
        store.require_f7_consumed_handle_v12(&handle)?;
        store.resume_xmr_bounded_claim_signing_locked_v23(chain, &handle)?
    };
    let baseline_ms = baseline_start.elapsed().as_millis();
    handle.observed_at.set(Instant::now());
    let start = Instant::now();
    let resumed = store.resume_post_anchor_dom_claim_signing_session_v12(&handle, chain)?;
    eprintln!(
        "CLAIM_RESUME_COST_V25 baseline_ms={baseline_ms} optimized_ms={}",
        start.elapsed().as_millis()
    );
    assert_eq!(
        baseline.accepted_signing_messages().collect::<Vec<_>>(),
        resumed.accepted_signing_messages().collect::<Vec<_>>()
    );
    assert_eq!(before.as_bytes(), store.load_session(session)?.as_bytes());

    handle
        .observed_at
        .set(Instant::now() - Duration::from_secs(61));
    assert!(store
        .resume_post_anchor_dom_claim_signing_session_v12(&handle, chain)
        .is_err());
    handle.observed_at.set(Instant::now());
    handle.consumption_digest[0] ^= 1;
    assert!(store
        .resume_post_anchor_dom_claim_signing_session_v12(&handle, chain)
        .is_err());
    handle.consumption_digest[0] ^= 1;
    for kind in ["claim-consumed", "claim-binding"] {
        let path = root
            .join("contracts/session-artifacts")
            .join(format!("{}.f7-v12-{kind}", hex_lower(&session)));
        let original = std::fs::read(&path)?;
        let mut corrupt = original.clone();
        *corrupt.last_mut().ok_or("empty record")? ^= 1;
        handle.observed_at.set(Instant::now());
        std::fs::write(&path, &corrupt)?;
        let result = store.resume_post_anchor_dom_claim_signing_session_v12(&handle, chain);
        std::fs::write(&path, &original)?;
        assert!(result.is_err(), "corrupt {kind} accepted");
    }
    handle.observed_at.set(Instant::now());
    store.resume_post_anchor_dom_claim_signing_session_v12(&handle, chain)?;
    assert_eq!(before.as_bytes(), store.load_session(session)?.as_bytes());
    Ok(())
}
