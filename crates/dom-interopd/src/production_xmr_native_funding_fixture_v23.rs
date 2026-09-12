//! Native component lifecycle, not daemon F6 admission or a chain payment.
//! Caller supplies roles derived from both actual leg templates.
use super::native_custody_v23::NativeXmrCustodyFixtureV23;
use crate::production_noise_relay::SignedNativeGraphFixtureV23;
use cap_std::fs::Dir;
use dom_adaptor::{AcceptedSigningSessionV1, PurposeV1};
use dom_final_claim_binding::FinalClaimRoleBindingV1;
use dom_scriptless_crypto::XmrRecoverySealKeyV11;
use dom_scriptless_identity_store::{
    ContractsIdentityPassphraseV1, ContractsTransportIdentityStoreV1,
};
use dom_scriptless_store::{
    ContractsSessionStoreV1, DomTransactionValidationContextV1, F7FundingGatePreparationV12,
    F7RecoveryPreparationV12, XmrGraphCustodyProvisioningStateV23,
    XmrOrdinaryRecoveryRoundSessionsV11, XmrRecoveryCustodyRoleV11, XmrRecoveryCustodyV11,
};
use std::{fs::File, path::Path, rc::Rc, sync::Arc};

#[path = "production_xmr_native_claim_fixture_v23.rs"]
pub(super) mod native_claim_v23;

type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

fn custody_stage<T, E: std::fmt::Display>(
    actor: usize,
    stage: &str,
    result: core::result::Result<T, E>,
) -> Result<T> {
    result.map_err(|error| format!("native custody actor={actor} {stage}: {error}").into())
}

pub(crate) fn custody_and_funding(
    signed: SignedNativeGraphFixtureV23,
    native: NativeXmrCustodyFixtureV23,
    roles: [FinalClaimRoleBindingV1; 2],
    work: [&Path; 2],
) -> Result<()> {
    let _retained = custody_and_funding_for_claim(signed, native, roles, work)?;
    Ok(())
}

/// Retain real owners for the separately observed native Claim continuation.
pub(super) fn custody_and_funding_for_claim(
    mut signed: SignedNativeGraphFixtureV23,
    mut native: NativeXmrCustodyFixtureV23,
    roles: [FinalClaimRoleBindingV1; 2],
    work: [&Path; 2],
) -> Result<(SignedNativeGraphFixtureV23, NativeXmrCustodyFixtureV23)> {
    let chain = signed.chain;
    let session = signed.wallets[0].0.session_id();
    let root = |actor: usize| -> Result<Dir> {
        Ok(Dir::from_std_file(custody_stage(
            actor,
            "open archive parent",
            File::open(work[actor]),
        )?))
    };
    let mut identities = Vec::new();
    let mut custody = Vec::new();
    let mut public_substitutes = Vec::new();
    let mut gates = Vec::new();
    let mut ordinary = Vec::new();
    // Explicit simulated DOM clock, independent of XMR's block-height deadline.
    // It is not an RPC observation and cannot authorize a network broadcast.
    let now = 1_000_010;
    let context = DomTransactionValidationContextV1::new(
        custody_stage(
            0,
            "load initial session",
            signed.stores[0].load_session(session),
        )?
        .chain()
        .tip_height,
        *chain.as_bytes(),
        now,
    );
    for actor in 0..2 {
        eprintln!("native custody actor={actor}: checking prefunding refusal");
        let store = &signed.stores[actor];
        let produced = &signed.produced[actor];
        let role = &roles[actor];
        let before = custody_stage(
            actor,
            "load prefunding session",
            store.load_session(session),
        )?;
        assert!(store
            .begin_f7_funding_signing_v20(chain, session, context)
            .is_err());
        assert!(signed.wallets[actor]
            .1
            .take_funding_share_v23(store)
            .is_err());
        assert_eq!(
            before.as_bytes(),
            custody_stage(actor, "reload refused session", store.load_session(session))?.as_bytes()
        );
        let identity_parent = custody_stage(
            actor,
            "open identity parent",
            File::open(work[actor].join("identity-parent")),
        )?;
        let passphrase = custody_stage(
            actor,
            "prepare identity passphrase",
            ContractsIdentityPassphraseV1::new(b"test-passphrase-v13".to_vec()),
        )?;
        let identity = custody_stage(
            actor,
            "open transport identity",
            ContractsTransportIdentityStoreV1::open_production(
                Arc::new(Dir::from_std_file(identity_parent)),
                "identity",
                &passphrase,
            ),
        )?;
        eprintln!("native custody actor={actor}: preparing authenticated graph permit");
        let permit = custody_stage(
            actor,
            "prepare graph custody permit",
            store.prepare_xmr_graph_custody_provisioning_v23(
                role,
                produced,
                [0xe1 + actor as u8; 32],
            ),
        )?;
        assert_eq!(permit.state(), XmrGraphCustodyProvisioningStateV23::Started);
        let stale_started = custody_stage(
            actor,
            "prepare second Started permit",
            store.prepare_xmr_graph_custody_provisioning_v23(
                role,
                produced,
                [0xe1 + actor as u8; 32],
            ),
        )?;
        let private = if permit.scope().role == XmrRecoveryCustodyRoleV11::PrivateRefundOwner {
            Some(custody_stage(
                actor,
                "complete private refund",
                native.complete_private_refund(actor, produced.graph()),
            )?)
        } else {
            None
        };
        eprintln!("native custody actor={actor}: creating encrypted archive");
        let archive_key = custody_stage(
            actor,
            "prepare archive seal key",
            XmrRecoverySealKeyV11::from_bytes(zeroize::Zeroizing::new([0xf1 + actor as u8; 32])),
        )?;
        let (archive, permit) = custody_stage(
            actor,
            "create encrypted graph archive",
            store.create_xmr_graph_custody_archive_v23(
                permit,
                root(actor)?,
                "native-xmr-recovery-v23",
                produced.graph(),
                archive_key,
                private.as_ref(),
            ),
        )?;
        drop(private);
        let (cancel_session, compensation_session) = produced.ordinary_sessions();
        eprintln!("native custody actor={actor}: auditing ordinary recovery rounds");
        let rounds = custody_stage(
            actor,
            "audit ordinary recovery rounds",
            store.audit_xmr_ordinary_recovery_rounds_v11(
                role,
                produced.graph(),
                produced.economic().policy(),
                &archive,
                XmrOrdinaryRecoveryRoundSessionsV11 {
                    cancel_session,
                    compensation_session,
                },
            ),
        )?;
        let prepare_gate = || {
            store.prepare_or_resume_xmr_bounded_f7_gate_v23(
                chain,
                F7FundingGatePreparationV12 {
                    role,
                    collateral: produced.collateral(),
                    funding_template: produced.graph().funding_template(),
                    claim_template: produced.graph().claim_template(),
                    recovery: F7RecoveryPreparationV12::XmrBoundedV23 {
                        produced,
                        custody: &archive,
                        ordinary_rounds: &rounds,
                        setup: native.setup(),
                    },
                    context,
                },
            )
        };
        assert!(
            prepare_gate().is_err(),
            "Started custody must not authorize F7"
        );
        custody_stage(
            actor,
            "mark graph custody Ready",
            store.mark_xmr_graph_custody_ready_v23(permit, &archive),
        )?;
        assert!(
            store
                .create_xmr_graph_custody_archive_v23(
                    stale_started,
                    root(actor)?,
                    "forbidden-ready-replacement-v23",
                    produced.graph(),
                    custody_stage(
                        actor,
                        "prepare stale-permit seal key",
                        XmrRecoverySealKeyV11::from_bytes(zeroize::Zeroizing::new(
                            [0xf1 + actor as u8; 32]
                        ))
                    )?,
                    None,
                )
                .is_err(),
            "stale Started permit must not create after Ready"
        );
        assert!(!work[actor].join("forbidden-ready-replacement-v23").exists());
        custody_stage(actor, "revalidate Ready archive", archive.revalidate())?;
        eprintln!("native custody actor={actor}: preparing bounded F7 gate");
        let gate = custody_stage(actor, "prepare Ready F7 gate", prepare_gate())?;
        let readiness = custody_stage(
            actor,
            "verify refund readiness",
            store.verify_xmr_refund_readiness_v23(&gate, &archive),
        )?;
        assert_eq!(readiness.chain_id(), chain.as_bytes());
        assert_eq!(readiness.session_id(), &session);
        assert_eq!(readiness.graph_digest(), produced.graph().graph_digest());
        assert_ne!(readiness.readiness_digest(), &[0; 32]);
        let public_substitute =
            if archive.scope().role == XmrRecoveryCustodyRoleV11::PrivateRefundOwner {
                let mut scope = *archive.scope();
                scope.role = XmrRecoveryCustodyRoleV11::PublicCounterparty;
                // A valid encrypted public archive with the SAME id and graph
                // must not satisfy the local U owner's authenticated Ready.
                let substitute_key = custody_stage(
                    actor,
                    "prepare public substitute key",
                    XmrRecoverySealKeyV11::from_bytes(zeroize::Zeroizing::new([0xc7; 32])),
                )?;
                let substitute = custody_stage(
                    actor,
                    "create public substitute archive",
                    XmrRecoveryCustodyV11::create(
                        root(actor)?,
                        "public-substitute-for-private-custody-v23",
                        scope,
                        produced.graph(),
                        substitute_key,
                        None,
                    ),
                )?;
                assert!(store
                    .validate_xmr_recovery_attachment_v12(&gate, &substitute)
                    .is_err());
                assert!(store
                    .verify_xmr_refund_readiness_v23(&gate, &substitute)
                    .is_err());
                Some(substitute)
            } else {
                None
            };
        public_substitutes.push(public_substitute);
        // Native readiness proves retained recovery, not a public final U
        // transaction or permission to fund before the bilateral Ready votes.
        assert!(
            matches!(
                store.authorize_xmr_recovery_execution_v12(&gate, &archive),
                Err(dom_scriptless_store::SessionStoreError::FundingAuthorityUnavailable)
            ),
            "attached recovery must wait before either Ready vote"
        );

        assert!(store.authorize_f7_funding_v12(&gate).is_err());
        assert!(store
            .begin_f7_funding_signing_v20(chain, session, context)
            .is_err());
        assert!(signed.wallets[actor]
            .1
            .take_funding_share_v23(store)
            .is_err());
        custody.push(archive);
        ordinary.push(rounds);
        gates.push(gate);
        identities.push(identity);
        eprintln!(
            "native custody actor={actor}: encrypted archive Ready and refusal checks passed"
        );
    }
    native = native
        .reopen(work)
        .map_err(|error| format!("native custody: reopen both private T/U owners: {error}"))?;
    eprintln!("native lifecycle: both encrypted archives Ready; private T/U reopened; funding still refused");
    for position in 0..2 {
        let mut selected = None;
        for actor in 0..2 {
            let vote = signed.stores[actor]
                .prepare_next_operational_xmr_ready_to_fund_vote_v12(&gates[actor])?
                .ok_or("missing readiness vote")?;
            if let Some(request) = signed.stores[actor]
                .prepare_xmr_ready_to_fund_dsc1_signing_request_v12(&gates[actor], &vote)?
            {
                selected = Some((actor, request));
                break;
            }
        }
        let (sender, request) = selected.ok_or("no native readiness sender")?;
        let peer = sender ^ 1;
        let peer_vote = signed.stores[peer]
            .prepare_next_operational_xmr_ready_to_fund_vote_v12(&gates[peer])?
            .ok_or("missing peer readiness vote")?;
        let committed = identities[sender]
            .sign_and_commit_store_prepared_dsc1(&signed.stores[sender], request)?;
        signed.stores[peer].accept_prepared_operational_xmr_ready_to_fund_vote_v12(
            &gates[peer],
            peer_vote,
            committed.signed_bytes(),
        )?;
        if position == 0 {
            for actor in 0..2 {
                assert!(signed.stores[actor]
                    .begin_f7_funding_signing_v20(chain, session, context)
                    .is_err());
                assert!(signed.wallets[actor]
                    .1
                    .take_funding_share_v23(&signed.stores[actor])
                    .is_err());
            }
        }
    }
    let graph_binding = signed.produced[0].graph().binding();
    let closed_height = graph_binding
        .cancel_height
        .checked_sub(graph_binding.reveal_safety_blocks)
        .ok_or("invalid XMR reveal window")?;
    let closed = DomTransactionValidationContextV1::new(closed_height, *chain.as_bytes(), now);
    assert!(signed.produced[0]
        .graph()
        .require_claim_window(closed_height)
        .is_err());
    let mut signers = Vec::new();
    let mut funding_paths = Vec::new();
    for actor in 0..2 {
        assert!(
            signed.stores[actor]
                .authorize_f7_funding_v12(&gates[actor])
                .is_err(),
            "raw authorization remains closed for the bounded profile"
        );
        let before = signed.stores[actor].load_session(session)?;
        assert!(signed.stores[actor].xmr_funding_window_open_v23(chain, session, context)?);
        assert!(!signed.stores[actor].xmr_funding_window_open_v23(chain, session, closed)?);
        let mut substituted_chain = *chain.as_bytes();
        substituted_chain[0] ^= 1;
        let wrong_chain =
            DomTransactionValidationContextV1::new(closed_height, substituted_chain, now);
        assert!(
            signed.stores[actor]
                .xmr_funding_window_open_v23(chain, session, wrong_chain)
                .is_err(),
            "a substituted chain must not become a recoverable closed window"
        );
        assert!(
            signed.stores[actor]
                .begin_f7_funding_signing_v20(chain, session, closed)
                .is_err(),
            "an early gate and two votes cannot extend the negotiated XMR window"
        );
        assert_eq!(
            before.as_bytes(),
            signed.stores[actor].load_session(session)?.as_bytes()
        );
        signed.stores[actor].begin_f7_funding_signing_v20(chain, session, context)?;
        let authorized_head = signed.stores[actor].load_session(session)?;
        assert!(!signed.stores[actor].xmr_funding_window_open_v23(chain, session, closed)?);
        assert!(signed.stores[actor].xmr_funding_window_open_v23(chain, session, context)?);
        assert_eq!(
            authorized_head.as_bytes(),
            signed.stores[actor].load_session(session)?.as_bytes(),
            "timing classification must not mutate the authorized round or its nonce state"
        );
        assert!(
            matches!(
                signed.stores[actor]
                    .authorize_xmr_recovery_execution_v12(&gates[actor], &custody[actor]),
                Err(dom_scriptless_store::SessionStoreError::FundingAuthorityUnavailable)
            ),
            "recovery must wait while the native Funding round is incomplete"
        );

        assert!(signed.stores[actor]
            .require_f7_funding_signing_window_v20(session, closed)
            .is_err());
        signed.stores[actor].require_f7_funding_signing_window_v20(session, context)?;
        let share = signed.wallets[actor]
            .1
            .take_funding_share_v23(&signed.stores[actor])?;
        assert!(signed.wallets[actor]
            .1
            .take_funding_share_v23(&signed.stores[actor])
            .is_err());
        let vault_names = || -> Result<std::collections::BTreeSet<std::path::PathBuf>> {
            let mut paths = std::collections::BTreeSet::new();
            for entry in std::fs::read_dir(work[actor])? {
                let entry = entry?;
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("dom-vault-v12-")
                    && entry.file_type()?.is_dir()
                {
                    paths.insert(entry.path());
                }
            }
            Ok(paths)
        };
        let before_vaults = vault_names()?;
        let unlock = zeroize::Zeroizing::new([0xb1 + actor as u8; 32]);
        let provisioner = crate::production_dom_vaults_v12::ProductionXmrGraphVaultKeyV23::retain(
            &unlock,
        )
        .mount(Arc::new(root(actor)?), signed.budget.clone(), false);
        let vault = provisioner.provision_funding_v23(
            &signed.stores[actor],
            signed.wallets[actor].0,
            chain,
        )?;
        assert_eq!(
            signed.stores[actor]
                .prepare_xmr_bounded_funding_vault_v23(chain, session)?
                .state(),
            dom_scriptless_store::XmrFundingVaultProvisioningStateV23::Ready
        );
        let created = vault_names()?
            .difference(&before_vaults)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            created.len(),
            1,
            "Funding must own one separate native root"
        );
        funding_paths.push(created.into_iter().next().ok_or("missing Funding root")?);
        signers.push(dom_actuator::participant_retained_vault_signer_v12(
            vault,
            Rc::clone(&signed.stores[actor]),
            signed.wallets[actor].0,
            chain,
            share,
        )?);
    }
    let mut messages = Vec::new();
    for position in 0..6 {
        let accepted = signed.stores[0].resume_xmr_bounded_funding_signing_v23(chain, session)?;
        let sender_id = accepted.roster().entries()[position % 2].participant_id();
        let sender = signed
            .wallets
            .iter()
            .position(|(binding, _)| &binding.participant().participant_id() == sender_id)
            .ok_or("missing funding sender")?;
        let peer = sender ^ 1;
        let transport = signed.stores[sender].prepare_operational_signing_transport_authority(
            chain,
            session,
            PurposeV1::Funding,
        )?;
        let accepted =
            signed.stores[sender].resume_xmr_bounded_funding_signing_v23(chain, session)?;
        assert_eq!(accepted.accepted_signing_messages().count(), position);
        let request =
            match crate::production_dom_claim_driver_v12::prepare_next_dom_funding_edge_v20(
                &signed.stores[sender],
                signed.wallets[sender].0,
                chain,
                &mut signers[sender],
                accepted,
                &transport,
            )? {
                crate::production_dom_claim_driver_v12::ProductionDomClaimProgressV12::Prepared(
                    request,
                ) => request,
                _ => return Err("funding edge did not produce request".into()),
            };
        let peer_transport = signed.stores[peer].prepare_operational_signing_transport_authority(
            chain,
            session,
            PurposeV1::Funding,
        )?;
        let committed = identities[sender]
            .sign_and_commit_store_prepared_dsc1(&signed.stores[sender], request)?;
        signed.stores[peer].accept_prepared_operational_signing_transport_message(
            &peer_transport,
            committed.signed_bytes(),
        )?;
        messages.push(committed.signed_bytes().to_vec());
    }
    let mut transactions = Vec::new();
    for actor in 0..2 {
        let transaction =
            signed.stores[actor].complete_f7_funding_signing_v20(chain, session, context)?;
        transactions.push(transaction.canonical_bytes().to_vec());
        let commit_path = work[actor]
            .join("runtime-contracts/session-artifacts")
            .join(format!("{}.f7-v12-funding", hex::encode(session)));
        let retained_commit = work[actor].join("funding-commit-retained-for-loss-test");
        assert!(!retained_commit.exists());
        std::fs::rename(&commit_path, &retained_commit)?;
        let lost_commit = signed.stores[actor]
            .authorize_xmr_recovery_execution_v12(&gates[actor], &custody[actor]);
        // Restore the same bytes before assertions; never delete the fixture.
        std::fs::rename(&retained_commit, &commit_path)?;
        assert!(
            matches!(
                lost_commit,
                Err(dom_scriptless_store::SessionStoreError::Quarantined)
            ),
            "a missing committed Funding journal must not become a retryable wait"
        );

        // Real native graph/custody and committed DOM funding still cannot
        // authorize compensation without the concrete XMR funding verifier.
        let recovery = signed.stores[actor]
            .authorize_xmr_recovery_execution_v12(&gates[actor], &custody[actor])?;
        assert!(
            recovery
                .require_bounded_compensation_v23(signed.produced[actor].graph(),)
                .is_err(),
            "DOM funding alone must never authorize XMR compensation"
        );
        if let Some(substitute) = &public_substitutes[actor] {
            assert!(
                recovery.require_custody(substitute).is_err(),
                "an issued recovery authority must still reject a public substitute for private U"
            );
            assert!(signed.stores[actor]
                .authorize_xmr_recovery_execution_v12(&gates[actor], substitute)
                .is_err());
        }

        assert!(signed.stores[actor]
            .require_f7_funding_transmission_v20(session, closed)
            .is_err());
        signed.stores[actor].require_f7_funding_transmission_v20(session, context)?;
        signed.stores[actor].revalidate_xmr_ordinary_recovery_rounds_v11(
            &ordinary[actor],
            &roles[actor],
            signed.produced[actor].graph(),
            signed.produced[actor].economic().policy(),
            &custody[actor],
        )?;
    }
    assert_eq!(transactions[0], transactions[1]);
    drop(signers);
    drop(identities);
    drop(custody);
    drop(public_substitutes);
    drop(ordinary);
    drop(gates);
    drop(signed.stores);
    native = native.reopen(work)?;
    let mut reopened = Vec::with_capacity(2);
    for actor in 0..2 {
        let store = ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
            Arc::new(root(actor)?),
            "runtime-contracts",
            signed.budget.clone(),
            chain,
        )?;
        let (produced, role) = store
            .retained_xmr_graph_custody_v23(chain, session, [0xe1 + actor as u8; 32])?
            .ok_or("Ready graph missing after restart")?;
        let scope = store.require_xmr_graph_custody_ready_v23(
            &role,
            &produced,
            [0xe1 + actor as u8; 32],
        )?;
        let archive = XmrRecoveryCustodyV11::open_existing(
            root(actor)?,
            "native-xmr-recovery-v23",
            scope,
            XmrRecoverySealKeyV11::from_bytes(zeroize::Zeroizing::new([0xf1 + actor as u8; 32]))?,
        )?;
        archive.revalidate()?;
        let (cancel_session, compensation_session) = produced.ordinary_sessions();
        let rounds = store.audit_xmr_ordinary_recovery_rounds_v11(
            &role,
            produced.graph(),
            produced.economic().policy(),
            &archive,
            XmrOrdinaryRecoveryRoundSessionsV11 {
                cancel_session,
                compensation_session,
            },
        )?;
        store.revalidate_xmr_ordinary_recovery_rounds_v11(
            &rounds,
            &role,
            produced.graph(),
            produced.economic().policy(),
            &archive,
        )?;
        let unlock = zeroize::Zeroizing::new([0xb1 + actor as u8; 32]);
        let provisioner = crate::production_dom_vaults_v12::ProductionXmrGraphVaultKeyV23::retain(
            &unlock,
        )
        .mount(Arc::new(root(actor)?), signed.budget.clone(), false);
        drop(provisioner.provision_funding_v23(&store, signed.wallets[actor].0, chain)?);
        // Losing Ready after actual local signing must not turn Started into
        // permission to provision again, even when the physical vault survives.
        let ready_record = work[actor]
            .join("runtime-contracts/session-rosters")
            .join(format!(
                "{}.xmr-funding-vault-ready-v23",
                hex::encode(session)
            ));
        let saved_ready = work[actor].join("funding-ready-record-retained-for-loss-test");
        assert!(!saved_ready.exists());
        std::fs::rename(&ready_record, &saved_ready)?;
        let lost_ready_refused =
            provisioner.provision_funding_v23(&store, signed.wallets[actor].0, chain);
        if ready_record.exists() {
            return Err(
                "Funding Ready was reissued after local signing; original retained beside it"
                    .into(),
            );
        }
        std::fs::rename(&saved_ready, &ready_record)?;
        assert!(
            lost_ready_refused.is_err(),
            "Started without Ready after local funding signing must refuse"
        );
        // Recoverable rename simulates missing Ready custody, never deletes it.
        let saved = work[actor].join("funding-vault-retained-for-missing-root-test");
        assert!(!saved.exists());
        std::fs::rename(&funding_paths[actor], &saved)?;
        let refused = provisioner.provision_funding_v23(&store, signed.wallets[actor].0, chain);
        if funding_paths[actor].exists() {
            return Err("Ready Funding vault was recreated; original retained beside it".into());
        }
        std::fs::rename(&saved, &funding_paths[actor])?;
        assert!(refused.is_err(), "missing Ready Funding vault must refuse");
        drop(provisioner.provision_funding_v23(&store, signed.wallets[actor].0, chain)?);
        let gate = store.resume_f7_funding_gate_v12(chain, session)?;
        assert_eq!(
            store
                .resume_f7_committed_funding_v12(&gate)?
                .canonical_bytes(),
            transactions[actor]
        );
        let transport = store.prepare_operational_signing_transport_authority(
            chain,
            session,
            PurposeV1::Funding,
        )?;
        let before = store.load_session(session)?;
        for bytes in &messages {
            store.accept_prepared_operational_signing_transport_message(&transport, bytes)?;
        }
        assert_eq!(before.as_bytes(), store.load_session(session)?.as_bytes());
        assert!(!before.irreversible().adaptor_secret_exposed);
        reopened.push(Rc::new(store));
    }
    signed.stores = reopened
        .try_into()
        .map_err(|_| "two reopened native Stores required")?;
    eprintln!("native lifecycle: six funding envelopes, identical durable bytes and reopen/replay verified; no broadcast");
    Ok((signed, native))
}
