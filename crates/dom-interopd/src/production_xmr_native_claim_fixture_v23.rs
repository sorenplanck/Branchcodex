//! Claim continuation for a funded native graph. This is deliberately not a
//! self-contained positive test: the caller must supply fresh, opaque evidence
//! from the concrete DOM/XMR verifier, not a planned txid or a sidecar echo.
//! Adaptation is explicit only after fresh F7 and accepted 0x0f; no broadcast.
//! Final exposed bytes remain behind the native submission capability.
use crate::production_noise_relay::SignedNativeGraphFixtureV23;
use cap_std::fs::Dir;
use dom_adaptor::{AcceptedSigningSessionV1, PurposeV1};
use dom_scriptless_identity_store::{
    ContractsIdentityPassphraseV1, ContractsTransportIdentityStoreV1,
};
use dom_scriptless_store::{ContractsSessionStoreV1, F7AnchorRequestBindingV12};
use f7_anchor_authority::families_v11::VerifiedF7AnchorAuthorizationV12;
use std::{fs::File, path::Path, rc::Rc, sync::Arc, time::Instant};
use xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12;

type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

/// The observation callback must run the concrete bounded verifier. Its opaque
/// return type has no public constructor; this helper cannot upgrade raw facts.
/// A missing observation is an error, never a skipped/passing Claim scenario.
pub(in super::super) fn claim_after_observed_funding(
    signed: SignedNativeGraphFixtureV23,
    work: [&Path; 2],
    native: &super::super::native_custody_v23::NativeXmrCustodyFixtureV23,
    mut capture: impl FnMut(
        &ContractsSessionStoreV1,
        dom_actuator::DomSessionBindingV1,
        &dom_actuator::DomF7FinalClaimSubmissionV14,
    ) -> Result<Vec<u8>>,
    mut receive: impl FnMut(&ContractsSessionStoreV1, usize, [u8; 32], &[u8]) -> Result<()>,
    mut observe: impl FnMut(
        usize,
        &F7AnchorRequestBindingV12,
        &ProducedXmrRecoveryGraphV12,
    ) -> Result<VerifiedF7AnchorAuthorizationV12>,
) -> Result<()> {
    let claim_started = Instant::now();
    eprintln!("native Claim: entering fresh observed-funding authorization and retained signing");
    let SignedNativeGraphFixtureV23 {
        stores,
        chain,
        budget,
        produced,
        mut wallets,
        ..
    } = signed;
    let session = wallets[0].0.session_id();
    let root = |actor: usize| -> Result<Dir> { Ok(Dir::from_std_file(File::open(work[actor])?)) };
    let mut identities = Vec::new();
    let mut authorities = Vec::new();
    let mut signers = Vec::new();
    for actor in 0..2 {
        let actor_started = Instant::now();
        let store = &stores[actor];
        let gate = store.resume_f7_funding_gate_v12(chain, session)?;
        // Require actual durable funding before asking for external evidence.
        let _funding = store.resume_f7_committed_funding_v12(&gate)?;
        let request = store.f7_anchor_request_binding_v12(&gate, chain)?;
        let evidence = observe(actor, &request, &produced[actor])?;
        let consumed = store.consume_f7_claim_authorization_v12(&gate, evidence)?;
        let accepted = store.bind_retained_f7_claim_signing_session_v12(&consumed, chain)?;
        assert_eq!(accepted.accepted_signing_messages().count(), 0);
        assert_eq!(accepted.purpose(), PurposeV1::ClaimAdaptor);
        let unlock = zeroize::Zeroizing::new([0xb1 + actor as u8; 32]);
        let provisioner = crate::production_dom_vaults_v12::ProductionXmrGraphVaultKeyV23::retain(
            &unlock,
        )
        .mount(Arc::new(root(actor)?), budget.clone(), false);
        let vault = provisioner.provision_claim_v23(store, wallets[actor].0, chain)?;
        let share = wallets[actor].1.take_claim_share_v23(store, &consumed)?;
        assert!(wallets[actor]
            .1
            .take_claim_share_v23(store, &consumed)
            .is_err());
        signers.push(dom_actuator::participant_retained_vault_signer_v12(
            vault,
            Rc::clone(store),
            wallets[actor].0,
            chain,
            share,
        )?);
        authorities.push(consumed);
        identities.push(ContractsTransportIdentityStoreV1::open_production(
            Arc::new(Dir::from_std_file(File::open(
                work[actor].join("identity-parent"),
            )?)),
            "identity",
            &ContractsIdentityPassphraseV1::new(b"test-passphrase-v13".to_vec())?,
        )?);
        eprintln!(
            "native Claim actor={actor}: fresh authority and retained signer ready after {:?}",
            actor_started.elapsed(),
        );
    }
    assert_eq!(stores.len(), 2);
    assert_eq!(wallets.len(), 2);
    let protocol_indices = [
        wallets[0].0.participant().protocol_index(),
        wallets[1].0.participant().protocol_index(),
    ];
    let mut messages = Vec::new();
    for position in 0..6 {
        let turn_started = Instant::now();
        // Refresh both process-bound consumed authorities with independent real
        // observations. Do not renew an old snapshot's timestamp locally.
        for actor in 0..2 {
            let gate = stores[actor].resume_f7_funding_gate_v12(chain, session)?;
            let request = stores[actor].f7_anchor_request_binding_v12(&gate, chain)?;
            stores[actor].revalidate_consumed_f7_claim_authorization_v12(
                &authorities[actor],
                observe(actor, &request, &produced[actor])?,
            )?;
        }
        // Public scheduling is not a signing capability. The selected owner
        // still performs its full audit below, following both fresh observers.
        let sender = super::native_sender_for_position_v24(protocol_indices, position)?;
        let peer = sender ^ 1;
        let accepted =
            stores[sender].resume_xmr_bounded_claim_signing_v23(chain, &authorities[sender])?;
        assert_eq!(accepted.accepted_signing_messages().count(), position);
        assert_eq!(accepted.roster().entries().len(), 2);
        assert_eq!(
            accepted.roster().entries()[position % 2].participant_id(),
            &wallets[sender].0.participant().participant_id(),
        );
        assert_eq!(
            accepted.roster().entries()[(position + 1) % 2].participant_id(),
            &wallets[peer].0.participant().participant_id(),
        );
        let transport = stores[sender].prepare_operational_signing_transport_authority(
            chain,
            session,
            PurposeV1::ClaimAdaptor,
        )?;
        let request = match crate::production_dom_claim_driver_v12::prepare_next_dom_claim_edge_with_signer_v12(
            &stores[sender], wallets[sender].0, chain, &mut signers[sender], accepted, &transport,
        )? {
            crate::production_dom_claim_driver_v12::ProductionDomClaimProgressV12::Prepared(request) => request,
            _ => return Err("native Claim did not prepare its next DSC1 edge".into()),
        };
        let peer_transport = stores[peer].prepare_operational_signing_transport_authority(
            chain,
            session,
            PurposeV1::ClaimAdaptor,
        )?;
        let committed =
            identities[sender].sign_and_commit_store_prepared_dsc1(&stores[sender], request)?;
        stores[peer].accept_prepared_operational_signing_transport_message(
            &peer_transport,
            committed.signed_bytes(),
        )?;
        messages.push(committed.signed_bytes().to_vec());
        eprintln!(
            "native Claim: envelope {position}, two fresh observations and both Stores verified after {:?}",
            turn_started.elapsed(),
        );
    }
    assert_eq!(messages.len(), 6);
    let pre_signature_started = Instant::now();
    // Refresh both consumed authorities with a fresh observation before the
    // pre-signature phase. The six signing rounds above can together span more
    // than MAX_V11_EXTERNAL_ANCHOR_AGE (60s) under the crypto-test profile, and
    // reconstruct/transport re-check observation recency exactly as every
    // signing round does, so a live caller re-observes here too.
    for actor in 0..2 {
        let gate = stores[actor].resume_f7_funding_gate_v12(chain, session)?;
        let request = stores[actor].f7_anchor_request_binding_v12(&gate, chain)?;
        stores[actor].revalidate_consumed_f7_claim_authorization_v12(
            &authorities[actor],
            observe(actor, &request, &produced[actor])?,
        )?;
    }
    let mut pre_bytes = Vec::new();
    let mut transports = Vec::new();
    for actor in 0..2 {
        let pre = stores[actor]
            .reconstruct_post_anchor_dom_claim_pre_signature_v12(&authorities[actor], chain)?;
        pre_bytes.push(pre.into_pre_signature().to_bytes());
        transports.push(
            stores[actor]
                .prepare_f7_claim_pre_signature_transport_v12(&authorities[actor], chain)?,
        );
    }
    assert_eq!(pre_bytes[0], pre_bytes[1]);
    for actor in 0..2 {
        assert!(
            stores[actor]
                .f7_claim_verification_facts_v15(
                    chain,
                    session,
                    wallets[actor].0.participant().participant_id(),
                )?
                .is_none(),
            "six messages and reconstructed pre are not accepted 0x0f"
        );
    }
    let mut publication = None;
    for actor in 0..2 {
        if let Some(request) = stores[actor]
            .prepare_f7_claim_pre_signature_dsc1_signing_request_v12(&transports[actor])?
        {
            assert!(
                publication.is_none(),
                "only the native canonical sender publishes 0x0f"
            );
            publication = Some((actor, request));
        }
    }
    let (sender, request) = publication.ok_or("no native 0x0f publisher")?;
    let committed =
        identities[sender].sign_and_commit_store_prepared_dsc1(&stores[sender], request)?;
    let pre_message = committed.signed_bytes().to_vec();
    stores[sender ^ 1].accept_prepared_f7_claim_pre_signature_transport_v12(
        &transports[sender ^ 1],
        &pre_message,
    )?;
    for actor in 0..2 {
        let gate = stores[actor].resume_f7_funding_gate_v12(chain, session)?;
        let request = stores[actor].f7_anchor_request_binding_v12(&gate, chain)?;
        let facts = stores[actor]
            .f7_claim_verification_facts_v15(
                chain,
                session,
                wallets[actor].0.participant().participant_id(),
            )?
            .ok_or("accepted native 0x0f must yield verifier facts")?;
        assert_eq!(
            facts.receiver_id(),
            request.role().final_claim_receiver_id().0
        );
    }
    eprintln!(
        "native Claim: identical pre-signatures and accepted 0x0f verified after {:?}",
        pre_signature_started.elapsed(),
    );
    drop(committed);
    drop(transports);
    drop(signers);
    drop(authorities);
    drop(identities);
    drop(stores);
    let mut captured = None;
    for actor in 0..2 {
        let actor_started = Instant::now();
        let store = ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
            Arc::new(root(actor)?),
            "runtime-contracts",
            budget.clone(),
            chain,
        )?;
        let gate = store.resume_f7_funding_gate_v12(chain, session)?;
        let request = store.f7_anchor_request_binding_v12(&gate, chain)?;
        let consumed = store.consume_f7_claim_authorization_v12(
            &gate,
            observe(actor, &request, &produced[actor])?,
        )?;
        let accepted = store.resume_xmr_bounded_claim_signing_v23(chain, &consumed)?;
        assert_eq!(accepted.accepted_signing_messages().count(), 6);
        let pre = store.reconstruct_post_anchor_dom_claim_pre_signature_v12(&consumed, chain)?;
        assert_eq!(pre.into_pre_signature().to_bytes(), pre_bytes[actor]);
        let unlock = zeroize::Zeroizing::new([0xb1 + actor as u8; 32]);
        let provisioner = crate::production_dom_vaults_v12::ProductionXmrGraphVaultKeyV23::retain(
            &unlock,
        )
        .mount(Arc::new(root(actor)?), budget.clone(), false);
        drop(provisioner.provision_claim_v23(&store, wallets[actor].0, chain)?);
        let before = store.load_session(session)?;
        let transport = store.prepare_operational_signing_transport_authority(
            chain,
            session,
            PurposeV1::ClaimAdaptor,
        )?;
        for message in &messages {
            store.accept_prepared_operational_signing_transport_message(&transport, message)?;
        }
        // Accepting the six retained transport messages replays the whole
        // growing transport-record scan and, under the crypto-test profile,
        // takes longer than MAX_V11_EXTERNAL_ANCHOR_AGE (60s). The freshly
        // consumed authority observed at consume time above is therefore stale
        // by the time the pre-signature transport is prepared, and
        // prepare_f7_claim_pre_signature_transport_v12 -> require_recent_observation
        // would reject it as ClaimSigningAuthorityUnavailable. Re-observe here,
        // mirroring both the signing loop and the pre-expose revalidate below;
        // this models a live caller and does not relax the 60s window.
        store.revalidate_consumed_f7_claim_authorization_v12(
            &consumed,
            observe(actor, &request, &produced[actor])?,
        )?;
        let pre_transport = store.prepare_f7_claim_pre_signature_transport_v12(&consumed, chain)?;
        store.accept_prepared_f7_claim_pre_signature_transport_v12(&pre_transport, &pre_message)?;
        assert_eq!(before.as_bytes(), store.load_session(session)?.as_bytes());
        assert!(!before.irreversible().adaptor_secret_exposed);
        let facts = store
            .f7_claim_verification_facts_v15(
                chain,
                session,
                wallets[actor].0.participant().participant_id(),
            )?
            .ok_or("accepted 0x0f must survive reopen as receiver facts")?;
        assert_eq!(
            facts.receiver_id(),
            request.role().final_claim_receiver_id().0
        );
        if request.role().dom_claim_sender_id().0 == wallets[actor].0.participant().participant_id()
        {
            eprintln!("DIAG sender actor={actor}: entered sender branch");
            // The effect is explicitly local component scope, not a fabricated
            // route coordinator/F6 grant. The actuator still fences it durably.
            let binding = wallets[actor].0;
            let effect = *dom_crypto::blake2b_256_tagged(
                "DOM-INTEROP/FIXTURE/NATIVE-CLAIM-EXPOSURE/V23",
                &session,
            )
            .as_bytes();
            let scope = dom_actuator::ScopedDomActionV1::new(
                binding,
                effect,
                dom_actuator::DomActionV1::BroadcastClaim,
            )?;
            let path = work[actor].join("native-claim-exposure-control-v23.sqlite");
            let mut control = dom_actuator::DomActuatorStoreV1::create(&path)?;
            let now = 2_000_000;
            let owner_id = effect;
            let lease = control.acquire_lease(
                binding.participant().participant_id(),
                owner_id,
                now,
                10_000,
            )?;
            control.bind_session(lease, binding, now)?;
            eprintln!("DIAG sender actor={actor}: lease+bind_session OK, testing wrong-side expose");
            // A valid actor on the opposite side must never release its U as T.
            assert!(native
                .expose_native_claim_v23(
                    actor ^ 1,
                    &store,
                    binding,
                    chain,
                    &consumed,
                    request.role(),
                    &mut control,
                    lease,
                    scope,
                    now,
                )
                .is_err());
            assert!(
                !store
                    .load_session(session)?
                    .irreversible()
                    .adaptor_secret_exposed
            );
            eprintln!("DIAG sender actor={actor}: wrong-side expose rejected OK, revalidating for real expose");
            store.revalidate_consumed_f7_claim_authorization_v12(
                &consumed,
                observe(actor, &request, &produced[actor])?,
            )?;
            eprintln!("DIAG sender actor={actor}: entering real expose_native_claim_v23");
            let submission = native.expose_native_claim_v23(
                actor,
                &store,
                binding,
                chain,
                &consumed,
                request.role(),
                &mut control,
                lease,
                scope,
                now,
            )?;
            eprintln!("DIAG sender actor={actor}: real expose OK");
            let tx_hash = submission.tx_hash();
            assert_ne!(tx_hash, [0; 32]);
            assert_eq!(
                store.f7_final_claim_progress_v14(chain, session)?,
                dom_scriptless_store::F7FinalClaimProgressV14::Exposed
            );
            let mirror = control.audit_final_claim_custody_v2(lease, binding, now)?;
            assert_eq!(mirror.tx_hash(), tx_hash);
            let exposure = mirror.exposure_record_digest();
            assert!(
                store
                    .load_session(session)?
                    .irreversible()
                    .adaptor_secret_exposed
            );
            // Capture through the real submission endpoint, but local HTTP503
            // grants no admission. Reopen both persistence boundaries below
            // and recover the same exposure without accessing T.
            let exact = capture(&store, binding, &submission)?;
            assert_eq!(
                dom_scriptless_chain_adapter::canonical_transaction_hash_v1(&exact)?,
                tx_hash
            );
            assert!(captured.replace((actor, exact)).is_none());
            assert_eq!(
                store.f7_final_claim_progress_v14(chain, session)?,
                dom_scriptless_store::F7FinalClaimProgressV14::Exposed
            );
            drop(submission);
            drop(consumed);
            drop(control);
            drop(store);
            let store = ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
                Arc::new(root(actor)?),
                "runtime-contracts",
                budget.clone(),
                chain,
            )?;
            let mut control = dom_actuator::DomActuatorStoreV1::open_existing(&path)?;
            let lease = control.acquire_lease(
                binding.participant().participant_id(),
                owner_id,
                now + 1,
                10_000,
            )?;
            eprintln!("DIAG sender actor={actor}: entering resume_f7_claim_child_v21 (second reopen)");
            dom_actuator::DomContractsActuatorV1::bind(&store, binding)?
                .resume_f7_claim_child_v21(&mut control, lease, &chain, scope, now + 1)?;
            eprintln!("DIAG sender actor={actor}: resume_f7_claim_child_v21 OK");
            let mirror = control.audit_final_claim_custody_v2(lease, binding, now + 1)?;
            assert_eq!(mirror.tx_hash(), tx_hash);
            assert_eq!(mirror.exposure_record_digest(), exposure);
            assert_eq!(
                store.f7_final_claim_progress_v14(chain, session)?,
                dom_scriptless_store::F7FinalClaimProgressV14::Exposed
            );
            assert!(
                store
                    .load_session(session)?
                    .irreversible()
                    .adaptor_secret_exposed
            );
        }
        eprintln!(
            "native Claim actor={actor}: independent reopen, replay and scoped exposure checks passed after {:?}",
            actor_started.elapsed(),
        );
    }
    let (sender, exact) = captured.ok_or("native exposed Claim was not captured")?;
    let receiver = sender ^ 1;
    for restart in 0..2 {
        let observation_started = Instant::now();
        let store = ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
            Arc::new(root(receiver)?),
            "runtime-contracts",
            budget.clone(),
            chain,
        )?;
        receive(
            &store,
            receiver,
            wallets[receiver].0.participant().participant_id(),
            &exact,
        )?;
        assert!(
            store
                .load_session(session)?
                .irreversible()
                .adaptor_secret_exposed
        );
        eprintln!(
            "native Claim receiver: canonical observation and extraction restart={restart} passed after {:?}",
            observation_started.elapsed(),
        );
    }
    eprintln!("native Claim: complete after {:?}", claim_started.elapsed());
    Ok(())
}
