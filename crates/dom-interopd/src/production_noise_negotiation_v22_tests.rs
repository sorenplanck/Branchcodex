// Real TCP/Noise adversarial negotiation; no fake transport or durable ack.
use super::*;

#[test]
fn graph_v22_unnegotiated_frames_preserve_pending_relay_after_reopen() -> TestResult {
    let temporary = TempDir::new()?;
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
    let refs = identity_references(&temporary)?;
    let alice_config = relay_config(0xb1, 32)?;
    let bob_config = relay_config(0xb2, 32)?;
    let bob_root = temporary.path().join("graph-refusal-bob");
    let (pending_key, pending) = envelope(BOB, ALICE, 0, 0x76)?;
    let d =
        dom_scriptless_crypto::xmr_cancelled_output_session_id_v22(&CHAIN, &SESSION, &[0x71; 32]);
    let mut recovery = RelayEnvelopeV1::decode(&pending)?;
    recovery.session_id = d;
    let recovery_key = IdempotencyKeyV1::of(&recovery);
    let recovery = recovery.canonical_bytes()?;
    {
        let mut relay = ProductionRelayV1::create(&bob_root, bob_config)?;
        relay.submit(&pending)?;
        relay.submit(&recovery)?;
    }

    // First advertise an unsupported graph capability; then negotiate only
    // C/D but inject a graph frame where the first Relay page must arrive.
    for advertise_graph in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let remote_parent = Arc::clone(&refs.parent);
        let remote_alice = refs.alice_session.clone();
        let remote_bob = refs.bob_session.clone();
        let remote_root = bob_root.clone();
        let responder = thread::spawn(move || -> TestResult {
            let identity = ContractsTransportIdentityStoreV1::open_production(
                remote_parent,
                "bob-identity",
                &passphrase()?,
            )?;
            let mut relay = ProductionRelayV1::open(&remote_root, bob_config)?;
            let (stream, _) = listener.accept()?;
            let error = cancelled_session(
                NoiseRoleV1::Responder,
                remote_bob,
                remote_alice,
                bob_config.database_id(),
                alice_config.database_id(),
            )?
            .exchange(&identity, &mut relay, stream)
            .expect_err("unnegotiated graph data must fail before Relay delivery");
            assert_eq!(error, ProductionNoiseRelayErrorV1::ProtocolRefused);
            Ok(())
        });
        let identity = ContractsTransportIdentityStoreV1::open_production(
            Arc::clone(&refs.parent),
            "alice-identity",
            &passphrase()?,
        )?;
        let session = cancelled_session(
            NoiseRoleV1::Initiator,
            refs.alice_session.clone(),
            refs.bob_session.clone(),
            alice_config.database_id(),
            bob_config.database_id(),
        )?;
        let stream =
            DeadlineTcpStreamV1::new(TcpStream::connect(address)?, session.exchange_timeout)?;
        let mut transport = identity.establish_noise_for_session(
            stream,
            session.role,
            CHAIN,
            SESSION,
            &session.local_reference,
            &session.remote_reference,
        )?;
        let hello = hello_v22::hello_body_v22(Some(&d), advertise_graph)?;
        session.send_frame(&mut transport, FrameKindV1::Hello, &hello)?;
        if !advertise_graph {
            session.receive_hello(&mut transport)?;
            session.send_frame(&mut transport, FrameKindV1::GraphOfferV22, b"unexpected")?;
        }
        let reply = session.receive_frame_bytes(&mut transport)?;
        let refused = session.decode_remote_frame(&reply)?;
        assert_eq!(refused.kind, FrameKindV1::Refused);
        assert!(refused.body.is_empty());
        responder
            .join()
            .map_err(|_| io::Error::other("graph refusal responder panicked"))??;

        // Reopen the actual durable database, not an in-memory delivery view.
        let relay = ProductionRelayV1::open(&bob_root, bob_config)?;
        assert_eq!(relay.stored_bytes(&pending_key)?, Some(pending.clone()));
        assert_eq!(relay.stored_bytes(&recovery_key)?, Some(recovery.clone()));
        for scope in [SESSION, d] {
            let scope = DeliveryScopeV3::new(ParticipantId(ALICE), ROUTE, scope)?;
            assert_eq!(relay.acknowledged_delivery_cursor_v3(&scope)?.position(), 0);
        }
    }
    Ok(())
}
