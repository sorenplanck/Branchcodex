//! Alternate OFFLINE branch copied before Claim. No second C/D proof run,
//! PoW assertion, broadcast receipt, or claim that both conflicting exits paid.
use super::*;
use cap_std::fs::Dir;
use dom_scriptless_crypto::XmrRecoverySealKeyV11;
use dom_scriptless_store::{
    ContractsSessionStoreV1, XmrRecoveryCustodyRoleV11, XmrRecoveryCustodyV11,
};
use std::{fs::File, os::unix::fs::DirBuilderExt, sync::Arc};

#[path = "production_xmr_native_recovery_copy_v23_tests.rs"]
mod private_copy;

pub(super) fn recover_on_private_fork(
    signed: &crate::production_noise_relay::SignedNativeGraphFixtureV23,
    native: &native_custody_v23::NativeXmrCustodyFixtureV23,
    work: [&Path; 2],
    funding: &mut FundingOwner,
    deployment: deployment_registry::ResolvedDomDeploymentV1,
    xmr_deployment: &deployment_registry::ResolvedMoneroDeploymentV1,
    funding_bytes: &[u8],
    funding_height: u64,
) -> Result<crate::production_child_xmr::XmrBuiltSweepV1> {
    let fork = tempfile::tempdir()?;
    let roots = [fork.path().join("actor-0"), fork.path().join("actor-1")];
    for actor in 0..2 {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&roots[actor])?;
        // The alternate transcript must also own an isolated identity journal:
        // signing its refund request must not consume the original Claim
        // continuation's DSC1 sequence or outbound signing record.
        for resource in [
            "runtime-contracts",
            "native-xmr-recovery-v23",
            "identity-parent",
        ] {
            private_copy::copy_tree(&work[actor].join(resource), &roots[actor].join(resource))?;
        }
    }
    let session = signed.wallets[0].0.session_id();
    let open = |actor: usize| -> Result<(ContractsSessionStoreV1, XmrRecoveryCustodyV11)> {
        let dir = || -> Result<Dir> { Ok(Dir::from_std_file(File::open(&roots[actor])?)) };
        let store = ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
            Arc::new(dir()?),
            "runtime-contracts",
            signed.budget.clone(),
            signed.chain,
        )?;
        let id = [0xe1 + actor as u8; 32];
        let (produced, role) = store
            .retained_xmr_graph_custody_v23(signed.chain, session, id)?
            .ok_or("fork lacks authenticated Ready custody")?;
        let scope = store.require_xmr_graph_custody_ready_v23(&role, &produced, id)?;
        let custody = XmrRecoveryCustodyV11::open_existing(
            dir()?,
            "native-xmr-recovery-v23",
            scope,
            XmrRecoverySealKeyV11::from_bytes(zeroize::Zeroizing::new([0xf1 + actor as u8; 32]))?,
        )?;
        Ok((store, custody))
    };
    let (_, first) = open(0)?;
    let private_actor = if first.scope().role == XmrRecoveryCustodyRoleV11::PrivateRefundOwner {
        0
    } else {
        1
    };
    drop(first);
    let public_actor = 1 - private_actor;
    let (store, custody) = open(private_actor)?;
    assert_eq!(
        custody.scope().role,
        XmrRecoveryCustodyRoleV11::PrivateRefundOwner
    );
    let gate = store.resume_f7_funding_gate_v12(signed.chain, session)?;
    let authority = store.authorize_xmr_recovery_execution_v12(&gate, &custody)?;
    let policy = authority.policy().policy();
    let cancel_height = policy.cancel_height;
    let minimum = u64::from(authority.minimum_confirmations());
    let cancel_at = cancel_height
        .checked_add(1)
        .ok_or("Cancel location overflow")?;
    let cancel_tip = cancel_at
        .checked_add(minimum.checked_sub(1).ok_or("zero finality")?)
        .ok_or("Cancel tip overflow")?;
    let refund_at = cancel_tip
        .checked_add(1)
        .ok_or("Refund location overflow")?;
    let refund_tip = refund_at
        .checked_add(minimum - 1)
        .ok_or("Refund tip overflow")?;
    if funding_height >= cancel_height
        || refund_tip
            .checked_add(policy.reveal_safety_blocks)
            .filter(|end| *end < policy.compensation_height)
            .is_none()
    {
        return Err("fixture must preserve the negotiated recovery window".into());
    }
    let cancel_hash = custody.with_graph(|g| {
        dom_scriptless_chain_adapter::canonical_transaction_hash_v1(g.cancel_bytes())
    })??;
    let refund_hash = custody.with_private_refund(|p| *p.transaction_hash())?;
    let archive_path = roots[private_actor].join("native-xmr-recovery-v23");
    assert!(!archive_path.join("xmr-cancel-attempt-v12.bin").exists());
    let snapshot = dom_snapshot::Snapshot::start_transactions_v23(
        deployment,
        &[(funding_bytes, funding_height)],
        cancel_height,
    )?;
    let runtime = snapshot.runtime()?;
    assert!(matches!(
        runtime.advance_xmr_recovery_v12(&authority, &custody),
        Err(adapter_dom_real::RealDomError::Chain(
            dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable
        ))
    ));
    let cancel = snapshot.take_submission_v23(cancel_hash)?;
    assert!(archive_path.join("xmr-cancel-attempt-v12.bin").is_file());
    assert!(!archive_path.join("xmr-cancel-admitted-v12.bin").exists());
    drop(runtime);
    snapshot.finish()?;
    drop(authority);
    drop(gate);
    drop(custody);
    drop(store);

    // Reopen both actual Store and archive after ambiguous Cancel submission.
    let (store, custody) = open(private_actor)?;
    let gate = store.resume_f7_funding_gate_v12(signed.chain, session)?;
    let authority = store.authorize_xmr_recovery_execution_v12(&gate, &custody)?;
    let snapshot = dom_snapshot::Snapshot::start_transactions_v23(
        deployment,
        &[(funding_bytes, funding_height), (&cancel, cancel_at)],
        cancel_tip,
    )?;
    let runtime = snapshot.runtime()?;
    assert!(!archive_path.join("xmr-refund-attempt-v12.bin").exists());
    assert!(matches!(
        runtime.advance_xmr_recovery_v12(&authority, &custody),
        Err(adapter_dom_real::RealDomError::Chain(
            dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable
        ))
    ));
    let refund = snapshot.take_submission_v23(refund_hash)?;
    assert!(archive_path.join("xmr-refund-attempt-v12.bin").is_file());
    assert!(!archive_path.join("xmr-refund-admitted-v12.bin").exists());
    drop(runtime);
    snapshot.finish()?;
    drop(authority);
    drop(gate);
    drop(custody);
    drop(store);

    // Real U bytes without the actual C->D ancestor cannot mint extraction.
    {
        let (store, custody) = open(public_actor)?;
        let gate = store.resume_f7_funding_gate_v12(signed.chain, session)?;
        let authority = store.authorize_xmr_recovery_execution_v12(&gate, &custody)?;
        let orphan = dom_snapshot::Snapshot::start_transactions_v23(
            deployment,
            &[(funding_bytes, funding_height), (&refund, refund_at)],
            refund_tip,
        )?;
        let runtime = orphan.runtime()?;
        assert!(matches!(
            runtime.observe_xmr_recovery_v12(&authority, &custody),
            Err(adapter_dom_real::RealDomError::InvalidEvidence)
        ));
        drop(runtime);
        orphan.finish()?;
    }

    // Peer U owner is no longer involved. The opposite Store/secret owner
    // re-reads the public canonical graph and extracts U through the scanner.
    let snapshot = dom_snapshot::Snapshot::start_transactions_v23(
        deployment,
        &[
            (funding_bytes, funding_height),
            (&cancel, cancel_at),
            (&refund, refund_at),
        ],
        refund_tip,
    )?;
    let runtime = snapshot.runtime()?;
    let (store, custody) = open(public_actor)?;
    assert_eq!(
        custody.scope().role,
        XmrRecoveryCustodyRoleV11::PublicCounterparty
    );
    let gate = store.resume_f7_funding_gate_v12(signed.chain, session)?;
    let authority = store.authorize_xmr_recovery_execution_v12(&gate, &custody)?;
    assert!(matches!(
        runtime.observe_xmr_recovery_v12(&authority, &custody)?,
        adapter_dom_real::VerifiedDomXmrRecoveryStateV11::Refunded(_)
    ));
    drop(authority);
    drop(gate);
    drop(custody);
    drop(store);
    // Reuse this fully signed graph and canonical U snapshot: transport races
    // must not be tested with a manually constructed native F7 capability.
    eprintln!("private-fork refund: canonical U observed; exercising refund transport");
    let transport_message = {
        let (store0, custody0) = open(0)?;
        let (store1, custody1) = open(1)?;
        native
            .assert_native_refund_transport_v24(
                [std::rc::Rc::new(store0), std::rc::Rc::new(store1)],
                [&custody0, &custody1],
                signed.chain,
                [signed.wallets[0].0, signed.wallets[1].0],
                &runtime,
                xmr_deployment,
                &funding.envelope.daemon_urls,
                &mut funding.port,
                [&roots[0], &roots[1]],
                [&roots[0], &roots[1]],
            )
            .map_err(|error| format!("assert_native_refund_transport_v24: {error}"))?
    };
    eprintln!("private-fork refund: refund transport asserted");
    let (store, custody) = open(public_actor)?;
    let retained = store
        .resume_pending_xmr_remote_sweep_request_for_local_signer(session)?
        .ok_or("native refund grant/request must survive original Store reopen")?;
    assert_eq!(retained.message_digest(), &transport_message);
    assert_eq!(
        xmr_remote_sweep_wire::RemoteSweepRequestV23::decode_exact(retained.payload())?.action,
        xmr_remote_sweep_wire::RemoteSweepActionV23::Refund,
    );
    let gate = store.resume_f7_funding_gate_v12(signed.chain, session)?;
    let authority = store.authorize_xmr_recovery_execution_v12(&gate, &custody)?;
    funding.require_alive()?;
    let sweep = native
        .build_observed_refund_sweep_v23(
            public_actor,
            &store,
            signed.wallets[public_actor].0,
            signed.chain,
            &runtime,
            &authority,
            &custody,
            &mut funding.port,
            *dom_crypto::blake2b_256_tagged("DOM/Fixture/NativeRefundSweep/V23\0", &session)
                .as_bytes(),
        )
        .map_err(|error| format!("build_observed_refund_sweep_v23: {error}"))?;
    assert!(!sweep.raw_transaction.is_empty());
    assert_ne!(sweep.key_image, [0; 32]);
    assert_ne!(sweep.tx_hash, [0; 32]);
    drop(runtime);
    snapshot.finish()?;
    Ok(sweep)
}
