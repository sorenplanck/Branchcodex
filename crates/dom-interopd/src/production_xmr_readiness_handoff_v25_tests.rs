//! Manual, bounded replay of an archived failed native ingress. The fixture
//! must be a private COPY; no live Store or original evidence is opened here.
use super::*;

/// Replay a completed real gate without running either daemon or a new ceremony.
#[test]
#[ignore = "manual archived Store replay; requires DOM_XMR_GATE_REPLAY_V25"]
fn archived_ready_gate_revalidates_original_markers_after_every_read(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(std::env::var("DOM_XMR_GATE_REPLAY_V25")?);
    let chain = dom_adaptor::TrustedChainIdV1::from_authenticated_genesis(
        dom_core::NETWORK_MAGIC_MAINNET,
        &dom_crypto::Hash256::from_bytes(dom_core::GENESIS_HASH_MAINNET),
    );
    let budget =
        dom_scriptless_store::BudgetPolicyV1::from_bytes(&std::fs::read(root.join("budget.bin"))?)?;
    let parent = std::sync::Arc::new(cap_std::fs::Dir::open_ambient_dir(
        &root,
        cap_std::ambient_authority(),
    )?);
    let store = ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
        std::sync::Arc::clone(&parent),
        "contracts",
        budget,
        chain,
    )?;
    let session = [0xa1; 32];
    let before = store.load_session(session)?.as_bytes().to_vec();
    let gate = store
        .retained_f7_funding_gate_v19(chain, session)?
        .ok_or("missing gate")?;
    let scope = store.expected_xmr_recovery_scope_v12(&gate)?;
    let key = zeroize::Zeroizing::new(std::fs::read(root.join("key.bin"))?);
    let mut key_bytes = zeroize::Zeroizing::new([0; 32]);
    key_bytes.copy_from_slice(&key);
    let custody = dom_scriptless_store::XmrRecoveryCustodyV11::open_existing(
        parent.try_clone()?,
        "custody",
        scope,
        dom_scriptless_crypto::XmrRecoverySealKeyV11::from_bytes(key_bytes)?,
    )?;
    let authority = store.authorize_xmr_recovery_execution_v12(&gate, &custody)?;
    assert_eq!(authority.session_id(), session);
    assert_eq!(authority.graph_digest(), scope.graph_digest);
    assert_eq!(authority.custody_id(), scope.custody_id);
    // Static graph authentication cannot manufacture fresh chain evidence.
    assert!(authority.require_xmr_funding_observed_v12().is_err());
    let (produced, role) = store
        .retained_xmr_graph_ready_for_activation_v23(chain, session)?
        .ok_or("missing retained graph")?;
    let (cancel_session, compensation_session) = produced.ordinary_sessions();
    let ordinary = store.audit_xmr_ordinary_recovery_rounds_v11(
        &role,
        produced.graph(),
        produced.economic().policy(),
        &custody,
        dom_scriptless_store::XmrOrdinaryRecoveryRoundSessionsV11 {
            cancel_session,
            compensation_session,
        },
    )?;
    let revalidate_rounds = || {
        store.revalidate_xmr_ordinary_recovery_rounds_v11(
            &ordinary,
            &role,
            produced.graph(),
            produced.economic().policy(),
            &custody,
        )
    };
    let baseline_start = std::time::Instant::now();
    store.require_xmr_graph_custody_ready_v23(&role, &produced, custody.scope().custody_id)?;
    revalidate_rounds()?;
    let baseline_ms = baseline_start.elapsed().as_millis();
    let combined =
        || store.revalidate_xmr_ready_custody_and_rounds_v25(&ordinary, &role, &produced, &custody);
    let start = std::time::Instant::now();
    combined()?;
    eprintln!(
        "CUSTODY_REVALIDATION_COST_V25 baseline_ms={baseline_ms} optimized_ms={}",
        start.elapsed().as_millis()
    );
    for state in ["started", "ready"] {
        let path = root.join("contracts/session-rosters").join(format!(
            "{}.xmr-graph-custody-{state}-v23",
            hex::encode(session),
        ));
        let original = std::fs::read(&path)?;
        let mut altered = original.clone();
        // Break the authenticated record, then restore this private test copy.
        let last = altered.last_mut().ok_or("empty custody record")?;
        *last ^= 1;
        std::fs::write(&path, altered)?;
        let corrupt = store.retained_f7_funding_gate_v19(chain, session);
        let corrupt_authority = store.authorize_xmr_recovery_execution_v12(&gate, &custody);
        let corrupt_rounds = revalidate_rounds();
        let corrupt_combined = combined();
        std::fs::write(&path, &original)?;
        assert!(
            corrupt_combined.is_err(),
            "altered {state} admitted combined audit"
        );
        assert!(
            corrupt_rounds.is_err(),
            "altered {state} admitted recovery rounds"
        );
        assert!(corrupt.is_err(), "altered {state} accepted");
        assert!(
            corrupt_authority.is_err(),
            "altered {state} authorized recovery"
        );
        assert!(store
            .retained_f7_funding_gate_v19(chain, session)?
            .is_some());

        std::fs::remove_file(&path)?;
        let missing = store.retained_f7_funding_gate_v19(chain, session);
        let missing_authority = store.authorize_xmr_recovery_execution_v12(&gate, &custody);
        let missing_rounds = revalidate_rounds();
        let missing_combined = combined();
        let recreated = path.exists();
        std::fs::write(&path, &original)?;
        assert!(missing.is_err(), "missing {state} accepted");
        assert!(
            missing_combined.is_err(),
            "missing {state} admitted combined audit"
        );
        assert!(
            missing_rounds.is_err(),
            "missing {state} admitted recovery rounds"
        );
        assert!(
            missing_authority.is_err(),
            "missing {state} authorized recovery"
        );
        assert!(!recreated, "missing {state} was manufactured");
        assert!(store
            .retained_f7_funding_gate_v19(chain, session)?
            .is_some());
    }
    assert_eq!(store.load_session(session)?.as_bytes(), before.as_slice());
    let resumed = store.authorize_xmr_recovery_execution_v12(&gate, &custody)?;
    assert_eq!(resumed.funding_tx_hash(), authority.funding_tx_hash());
    assert_eq!(resumed.graph_digest(), authority.graph_digest());
    revalidate_rounds()?;
    combined()?;
    Ok(())
}

#[test]
#[ignore = "manual archived Store replay; requires DOM_XMR_READINESS_REPLAY_V25"]
fn archived_first_readiness_waits_without_accepting_or_mutating(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(std::env::var("DOM_XMR_READINESS_REPLAY_V25")?);
    let signed = std::fs::read(root.join("ready.dsc1"))?;
    let message = SignedMessageV1::decode_exact(&signed)?;
    assert_eq!(message.unsigned().kind() as u8, 0x17);
    let chain = dom_adaptor::TrustedChainIdV1::from_authenticated_genesis(
        dom_core::NETWORK_MAGIC_MAINNET,
        &dom_crypto::Hash256::from_bytes(dom_core::GENESIS_HASH_MAINNET),
    );
    assert_eq!(chain.as_bytes(), message.unsigned().chain_id());
    let budget =
        dom_scriptless_store::BudgetPolicyV1::from_bytes(&std::fs::read(root.join("budget.bin"))?)?;
    let parent = std::sync::Arc::new(cap_std::fs::Dir::open_ambient_dir(
        &root,
        cap_std::ambient_authority(),
    )?);
    let store = Rc::new(
        ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
            parent,
            "contracts",
            budget,
            chain,
        )?,
    );
    let session = *message.unsigned().session_id();
    assert!(store
        .retained_f7_funding_gate_v19(chain, session)?
        .is_none());
    let before = store.load_session(session)?.as_bytes().to_vec();
    let prepared = store.prepare_xmr_graph_signing_ingress_v23(
        session,
        dom_scriptless_store::XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
    )?;
    let local: [u8; 32] = std::fs::read(root.join("local-id.bin"))?
        .try_into()
        .map_err(|_| "local id length")?;
    let mut port = ContractsStoreTransportPortV1::new(
        Rc::clone(&store),
        session,
        ParticipantId(local),
        ParticipantId(*message.unsigned().sender_id()),
    )?;
    port.install(PreparedContractsIngressV1::xmr_graph_signing_v23(prepared))?;
    assert!(matches!(
        port.accept_unseen(&signed),
        Err(ContractsRelayIngressErrorV1::AwaitingNativeXmrReadinessGateV25)
    ));
    // Every changed scope, sequence, transcript, payload or signature must be
    // rejected; retaining the authentic vote never authenticates altered bytes.
    for offset in [8, 40, 72, 104, 112, 148, signed.len() - 1] {
        let mut altered = signed.clone();
        altered[offset] ^= 1;
        assert!(!matches!(
            port.accept_unseen(&altered),
            Err(ContractsRelayIngressErrorV1::AwaitingNativeXmrReadinessGateV25)
        ));
        assert!(port.accept_unseen(&altered).is_err());
    }
    assert_eq!(store.load_session(session)?.as_bytes(), before.as_slice());
    assert!(store
        .retained_f7_funding_gate_v19(chain, session)?
        .is_none());
    Ok(())
}
