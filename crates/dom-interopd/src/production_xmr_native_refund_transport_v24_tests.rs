//! Native signed Store + durable Relay inbox regression, reused by the real
//! output-scan component test. This is NOT daemon F6 admission or a payment.
//! The component route/effect labels below authorize no XMR build or import.
use super::*;
use btc_crypto::SecpContext;
use cap_std::fs::Dir;
use dom_scriptless_identity_store::{
    ContractsIdentityPassphraseV1, ContractsTransportIdentityStoreV1,
};
use dom_scriptless_store::{ContractsSessionStoreV1, SessionStoreError, XmrRecoveryCustodyV11};
use relay::auth::{message_type, RosterMemberV1, RosterRegistryV1, RosterSnapshotV1};
use relay::production::{ProductionRelayV1, RelayDatabaseConfigV1, RelayDatabaseIdV1};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1};
use route_transport::{
    DurableInboxConfigV1, DurableRelayInboxV1, RouteDispatchErrorV1, RouteWireContextV1,
};
use std::{fs::File, rc::Rc, sync::Arc};
use xmr_remote_sweep_wire::{RemoteSweepActionV23, RemoteSweepLegV23, RemoteSweepRequestV23};

impl NativeXmrCustodyFixtureV23 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assert_native_refund_transport_v24(
        &self,
        stores: [Rc<ContractsSessionStoreV1>; 2],
        custody: [&XmrRecoveryCustodyV11; 2],
        chain: dom_adaptor::TrustedChainIdV1,
        bindings: [dom_actuator::DomSessionBindingV1; 2],
        runtime: &adapter_dom_real::RealDomRpcRuntimeV1,
        deployment: &deployment_registry::ResolvedMoneroDeploymentV1,
        urls: &[String],
        sidecar: &mut xmr_live_sidecar_uds_client::BlockingUdsSidecarPort,
        identity_roots: [&Path; 2],
        store_roots: [&Path; 2],
    ) -> Result<[u8; 32]> {
        let sender = self
            .actors
            .iter()
            .position(|owner| owner.role == XmrLocalShareRoleV11::ClaimReceiver)
            .ok_or("native refund request needs original ClaimReceiver")?;
        let receiver = sender ^ 1;
        let session = bindings[sender].session_id();
        assert_eq!(session, bindings[receiver].session_id());
        let gate = stores[sender].resume_f7_funding_gate_v12(chain, session)?;
        let anchors = stores[sender].f7_anchor_request_binding_v12(&gate, chain)?;
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let funding = tokio.block_on(f7_anchor_authority::families_v11::verify_xmr_funding_v11(
            f7_anchor_authority::families_v11::XmrFundingObservationRequestV11 {
                terms: anchors.role().terms(),
                setup: &self.setup,
                profile: &self.profile,
                deployment,
                daemon_urls: urls,
            },
            sidecar,
            &self.actors[sender].secrets,
        ))?;
        drop(tokio);
        let observe = |actor: usize| -> Result<adapter_dom_real::VerifiedDomRefundSecretV11> {
            let gate = stores[actor].resume_f7_funding_gate_v12(chain, session)?;
            let authority =
                stores[actor].authorize_xmr_recovery_execution_v12(&gate, custody[actor])?;
            let adapter_dom_real::VerifiedDomXmrRecoveryStateV11::Refunded(observed) =
                runtime.observe_xmr_recovery_v12(&authority, custody[actor])?
            else {
                return Err("native final U required for refund transport".into());
            };
            observed.require_recent_v23()?;
            Ok(observed)
        };
        let observed = observe(sender)?;
        let refund_claim = xmr_refund_adaptor::verify_refund_bundle(
            &self.refund_proof,
            &self.setup.settlement_id(),
            self.setup.proof_context_hash(),
        )?;
        assert_eq!(observed.refund_point(), refund_claim.secp_compressed);
        let public_share = observed.expose(|bytes| {
            xmr_dleq_sigma::revealed_dom_secret_to_xmr_scalar(*bytes, &refund_claim)
        })?;
        let event = stores[sender].native_xmr_refund_transport_public_evidence_v23(
            &gate,
            custody[sender],
            observed.finality().transaction_hash(),
        )?;
        let component = *dom_crypto::blake2b_256_tagged(
            "DOM/Fixture/NativeRefundTransportOnly/V24\0",
            &session,
        )
        .as_bytes();
        let request = RemoteSweepRequestV23 {
            network_genesis: deployment.deployment().genesis_hash,
            route_id: component,
            session_id: session,
            settlement_id: self.setup.settlement_id(),
            terms_digest: self.setup.terms_hash(),
            registry_digest: deployment.registry_digest(),
            profile_digest: deployment.profile_digest(),
            deployment_digest: deployment.asset_binding_digest(),
            route_scope_digest: component,
            composition_digest: component,
            role_plan_digest: anchors.role().digest()?,
            source_scope_digest: component,
            effect_id: component,
            semantic_digest: component,
            public_secret_evidence_digest: event,
            funding_tx_hash: self.setup.funding_tx_hash(),
            funding_evidence_digest: *funding.evidence_digest(),
            funding_output_index: u64::from(funding.output_index()),
            funding_block_height: funding.block_height(),
            funded_amount_piconero: self.setup.expected_amount_piconero(),
            max_fee_piconero: self
                .claim_payout_v23
                .as_ref()
                .ok_or("refund payout missing")?
                .max_fee,
            adapter_max_raw_transaction_bytes: self.profile.max_raw_tx_bytes,
            max_raw_transaction_bytes: self.profile.max_raw_tx_bytes.min(u32::try_from(
                xmr_remote_sweep_wire::MAX_RAW_SWEEP_BYTES_V23,
            )?),
            fencing_epoch: 1,
            action: RemoteSweepActionV23::Refund,
            leg: RemoteSweepLegV23::Upstream,
            public_spend_share: public_share,
            destination: self
                .claim_payout_v23
                .as_ref()
                .ok_or("refund payout missing")?
                .refund_address()
                .to_owned(),
        };
        let request_bytes = request.encode()?;
        // Only the sender has independently installed its transport grant.
        // A legitimate message can therefore race the recipient's U observer.
        observed.require_recent_v23()?;
        stores[sender].retain_native_xmr_refund_transport_v23(
            &gate,
            custody[sender],
            &request_bytes,
            observed.finality().transaction_hash(),
        )?;
        observed.require_recent_v23()?;
        let identity = ContractsTransportIdentityStoreV1::open_production(
            Arc::new(Dir::from_std_file(File::open(
                identity_roots[sender].join("identity-parent"),
            )?)),
            "identity",
            &ContractsIdentityPassphraseV1::new(b"test-passphrase-v13".to_vec())?,
        )?;
        let prepared = stores[sender]
            .prepare_xmr_remote_sweep_request_dsc1_signing_request(session, &request_bytes)?;
        let signed = identity.sign_and_commit_store_prepared_dsc1(&stores[sender], prepared)?;
        let signed_bytes = signed.signed_bytes().to_vec();
        let sender_id = ParticipantId(bindings[sender].participant().participant_id());
        let receiver_id = ParticipantId(bindings[receiver].participant().participant_id());
        let before = stores[receiver].load_session(session)?.as_bytes().to_vec();
        assert!(matches!(
            stores[receiver].accept_xmr_remote_sweep_request_transport_message(&signed_bytes),
            Err(SessionStoreError::NativeXmrRefundTransportPendingV23)
        ));
        let mut invalid = signed_bytes.clone();
        let last = invalid.len() - 1;
        invalid[last] ^= 1;
        assert!(
            !matches!(
                stores[receiver].accept_xmr_remote_sweep_request_transport_message(&invalid),
                Ok(_) | Err(SessionStoreError::NativeXmrRefundTransportPendingV23)
            ),
            "bad signatures must not be classified as pending U"
        );
        assert_eq!(before, stores[receiver].load_session(session)?.as_bytes());

        let directory = tempfile::tempdir()?;
        // The durable inbox refuses any parent that is not owner-only, and
        // tempfile honors the ambient umask (0o022 on CI turns the fresh
        // directory into 0o755). Pin the exact owner-only mode explicitly.
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;
        let secret = [0x71; 32];
        let secp = SecpContext::new(&[0x55; 32]);
        let xonly = secp.sign_bip340(&secret, &[0; 32], &[0x56; 32])?.1;
        let snapshot =
            *dom_crypto::blake2b_256_tagged("DOM/Fixture/RefundRelayRoster/V24\0", &session)
                .as_bytes();
        let wire = RouteWireContextV1 {
            network_id: *chain.as_bytes(),
            session_id: session,
            route_id: component,
            roster_snapshot: snapshot,
            policy_version: 1,
        };
        let rosters = RosterRegistryV1::new().with_snapshot(
            snapshot,
            RosterSnapshotV1::new()
                .with_member(
                    sender_id,
                    RosterMemberV1 {
                        xonly_key: xonly,
                        role: SenderRoleV1::Initiator,
                    },
                )
                .with_member(
                    receiver_id,
                    RosterMemberV1 {
                        xonly_key: secp.sign_bip340(&[0x72; 32], &[0; 32], &[0x57; 32])?.1,
                        role: SenderRoleV1::Solver,
                    },
                ),
        );
        let database_id = [0xd1; 32];
        let config = DurableInboxConfigV1::new([0x54; 32], database_id, wire, receiver_id, 16)?;
        let inbox_path = directory.path().join("inbox");
        let mut inbox = DurableRelayInboxV1::create(&inbox_path, config, &rosters)?;
        let mut relay = ProductionRelayV1::create(
            &directory.path().join("relay"),
            RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new(database_id)?, 16)?,
        )?;
        let outer = |sequence, previous| -> Result<(Vec<u8>, [u8; 32])> {
            let mut envelope = RelayEnvelopeV1 {
                network_id: wire.network_id,
                message_type: message_type::ROUTE_TRANSPORT,
                session_id: session,
                route_id: component,
                sender_id,
                recipient_id: receiver_id,
                sender_role: SenderRoleV1::Initiator,
                sequence,
                previous_transcript_hash: previous,
                payload: signed_bytes.clone(),
                expiry: TimelockSpec::TimestampSeconds { value: 10_000 },
                policy_version: 1,
                roster_snapshot: snapshot,
                signature: [0; 64],
            };
            let digest = envelope.envelope_digest()?;
            envelope.signature = secp.sign_bip340(&secret, &digest, &[0x58; 32])?.0;
            Ok((envelope.canonical_bytes()?, digest))
        };
        let (outer_bytes, outer_digest) = outer(0, [0; 32])?;
        relay.submit(&outer_bytes)?;
        let now = TimelockSpec::TimestampSeconds { value: 1_000 };
        assert_eq!(inbox.ingest(&mut relay, &rosters, now)?.accepted, 1);
        let mut port = crate::relay_worker::native_refund_transport_test_port_v24(
            Rc::clone(&stores[receiver]),
            session,
            receiver_id,
            sender_id,
        )?;
        assert!(matches!(inbox.dispatch_routes(&mut port),
            Err(RouteDispatchErrorV1::Contracts(crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingNativeXmrRefundTransportV23))));
        assert_eq!(inbox.stats()?.pending_route, 1);
        assert_eq!(inbox.stats()?.delivered, 0, "pending is not a receipt");
        assert_eq!(before, stores[receiver].load_session(session)?.as_bytes());
        drop(inbox);
        let mut inbox = DurableRelayInboxV1::open(&inbox_path, config, &rosters)?;
        assert_eq!(inbox.stats()?.pending_route, 1);
        // Install only through the real native observer and custody producer.
        let observed = observe(receiver)?;
        let receiver_gate = stores[receiver].resume_f7_funding_gate_v12(chain, session)?;
        let mut receiver_scope = request.clone();
        receiver_scope.effect_id = *dom_crypto::blake2b_256_tagged(
            "DOM/Fixture/NativeRefundReceiverEffect/V24\0",
            &session,
        )
        .as_bytes();
        receiver_scope.fencing_epoch += 1;
        receiver_scope.semantic_digest = *dom_crypto::blake2b_256_tagged(
            "DOM/Fixture/NativeRefundReceiverSemantics/V24\0",
            &session,
        )
        .as_bytes();
        stores[receiver].retain_native_xmr_refund_transport_v23(
            &receiver_gate,
            custody[receiver],
            &receiver_scope.encode()?,
            observed.finality().transaction_hash(),
        )?;
        observed.require_recent_v23()?;
        assert_eq!(inbox.dispatch_routes(&mut port)?.applied, 1);
        assert_eq!(inbox.stats()?.pending_route, 0);
        assert_eq!(inbox.stats()?.delivered, 1);
        let accepted_head = stores[receiver].load_session(session)?.as_bytes().to_vec();
        stores[receiver].accept_xmr_remote_sweep_request_transport_message(&signed_bytes)?;
        assert_eq!(
            accepted_head,
            stores[receiver].load_session(session)?.as_bytes()
        );
        drop(inbox);
        let mut inbox = DurableRelayInboxV1::open(&inbox_path, config, &rosters)?;
        assert_eq!(inbox.stats()?.delivered, 1);
        assert_eq!(inbox.dispatch_routes(&mut port)?.applied, 0);

        let grant_path = store_roots[receiver]
            .join("runtime-contracts/session-artifacts")
            .join(format!(
                "{}.f7-v12-refund-transport-v23",
                hex::encode(session)
            ));
        let original = std::fs::read(&grant_path)?;
        // Exact same inner message in a valid next outer envelope. This does
        // not renew an expired/unaccepted envelope or alter Relay sequencing.
        let (retry, _) = outer(1, outer_digest)?;
        relay.submit(&retry)?;
        assert_eq!(inbox.ingest(&mut relay, &rosters, now)?.accepted, 1);
        let mut corrupt = original.clone();
        corrupt[8] ^= 1;
        std::fs::write(&grant_path, &corrupt)?;
        let refused = inbox.dispatch_routes(&mut port);
        std::fs::write(&grant_path, &original)?;
        assert!(matches!(
            refused,
            Err(RouteDispatchErrorV1::Contracts(
                crate::relay_worker::ContractsRelayIngressErrorV1::Store(
                    SessionStoreError::Quarantined
                )
            ))
        ));
        assert_eq!(inbox.stats()?.pending_route, 1);
        assert_eq!(inbox.stats()?.delivered, 1);
        assert_eq!(
            accepted_head,
            stores[receiver].load_session(session)?.as_bytes()
        );
        let retained = store_roots[receiver].join("refund-transport-retained-loss-test-v24");
        assert!(!retained.exists());
        std::fs::rename(&grant_path, &retained)?;
        let missing = inbox.dispatch_routes(&mut port);
        std::fs::rename(&retained, &grant_path)?;
        assert!(matches!(
            missing,
            Err(RouteDispatchErrorV1::Contracts(
                crate::relay_worker::ContractsRelayIngressErrorV1::Store(
                    SessionStoreError::Quarantined
                )
            ))
        ));
        assert_eq!(
            inbox.stats()?.pending_route,
            1,
            "loss after retention must not mint receipt"
        );
        assert_eq!(inbox.dispatch_routes(&mut port)?.applied, 1);
        assert_eq!(inbox.stats()?.delivered, 2);
        assert_eq!(
            accepted_head,
            stores[receiver].load_session(session)?.as_bytes()
        );
        eprintln!("native refund transport: signed pending, durable replay, tamper and grant loss covered");
        let retained = stores[receiver]
            .resume_pending_xmr_remote_sweep_request_for_local_signer(session)?
            .ok_or("accepted native refund request disappeared")?;
        assert_eq!(retained.payload(), request_bytes);
        Ok(*retained.message_digest())
    }
}
