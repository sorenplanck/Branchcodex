//! Called by the real two-wallet C/D fixture, not by a synthetic packet fixture.
use super::*;
use cap_std::fs::Dir;
use dom_scriptless_identity_store::ContractsIdentityPassphraseV1;
use relay::production::RelayDatabaseConfigV1;
use std::{
    error::Error, fs::File, net::TcpListener, os::unix::fs::PermissionsExt, sync::Arc, thread,
};

type TestError = Box<dyn Error + Send + Sync>;
#[path = "production_xmr_graph_signing_v23_tests.rs"]
mod signing_v23;
pub(crate) use signing_v23::SignedNativeGraphFixtureV23;

fn passphrase() -> Result<ContractsIdentityPassphraseV1, TestError> {
    Ok(ContractsIdentityPassphraseV1::new(
        b"native XMR graph transport test identity".to_vec(),
    )?)
}

fn copy_context(
    graph: &ProductionNoiseGraphOfferV22,
) -> Result<ProductionNoiseGraphOfferV22, TestError> {
    Ok(ProductionNoiseGraphOfferV22::new(
        graph.route_id,
        graph.terms.clone(),
        graph.policy.clone(),
        graph.native.clone(),
        graph.local.clone(),
    )?)
}

fn session(
    role: NoiseRoleV1,
    graph: ProductionNoiseGraphOfferV22,
    local: SessionTransportIdentityReferenceV1,
    remote: SessionTransportIdentityReferenceV1,
    local_db: RelayDatabaseIdV1,
    remote_db: RelayDatabaseIdV1,
) -> Result<ProductionNoiseRelaySessionV1, TestError> {
    let chain = *graph.native.chain_id();
    let parent_session = *graph.native.session_id();
    let terms = *graph.native.terms_hash();
    let route = graph.route_id;
    let build = |session_id| {
        ProductionNoiseRelaySessionV1::new(
            role,
            ProductionNoiseRelayRouteContextV1::new(chain, [0x65; 32], route, session_id)?,
            [local.clone(), remote.clone()],
            ProductionNoiseRelayDatabasePairV1::new(local_db, remote_db)?,
            Duration::from_secs(60),
        )
    };
    let parent = build(parent_session)?;
    let cancelled = build(dom_scriptless_crypto::xmr_cancelled_output_session_id_v22(
        &chain,
        &parent_session,
        &terms,
    ))?;
    Ok(parent
        .with_xmr_cancelled_v22(cancelled, terms)?
        .with_xmr_graph_offer_v22(graph)?)
}

impl ProductionNoiseGraphOfferV22 {
    /// Forms the second leg from its own native C/D proofs and wallet offers.
    /// No signing origin, journal, nonce or signature is manufactured here.
    pub(crate) fn test_form_claim_template_hash_v23(
        graphs: &[Self; 2],
        c: [Option<(
            dom_scriptless_crypto::FrozenSharedOutputV1,
            dom_adaptor::VerifiedSharedOutputV1,
        )>; 2],
        d: [Option<(
            dom_scriptless_crypto::FrozenSharedOutputV1,
            dom_adaptor::VerifiedSharedOutputV1,
        )>; 2],
        refund_point: [u8; 33],
    ) -> Result<[u8; 32], TestError> {
        use xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningStageV22 as Stage;
        let mut hashes = Vec::with_capacity(2);
        for (actor, (c, d)) in c.into_iter().zip(d).enumerate() {
            let public = graphs[actor].assemble_peer_material_v22(&graphs[actor ^ 1].local)?;
            let formed = crate::production_relay_stage12::graph_v23::form_xmr_graph_templates_v23(
                &public,
                &graphs[actor].terms,
                &graphs[actor].policy,
                [
                    c.ok_or("missing second-leg native C")?,
                    d.ok_or("missing second-leg native D")?,
                ],
                10,
                refund_point,
            )?;
            formed.keys.require_route(graphs[actor].route_id)?;
            formed.keys.require_graph(&formed.templates)?;
            hashes.push(formed.keys.template_hash(Stage::Claim));
        }
        if hashes.len() != 2 || hashes[0] != hashes[1] {
            return Err("second-leg canonical Claim templates disagree".into());
        }
        Ok(hashes[0])
    }

    /// Real wallet offers plus journal-reconstructed C/D proofs. The public U
    /// fixture isolates formation; this does not authenticate XMR setup or sign.
    pub(crate) fn test_form_native_graphs_v23(
        graphs: &[Self; 2],
        work: [&std::path::Path; 2],
        budget: dom_scriptless_store::BudgetPolicyV1,
        c: [Option<(
            dom_scriptless_crypto::FrozenSharedOutputV1,
            dom_adaptor::VerifiedSharedOutputV1,
        )>; 2],
        d: [Option<(
            dom_scriptless_crypto::FrozenSharedOutputV1,
            dom_adaptor::VerifiedSharedOutputV1,
        )>; 2],
        signing_wallets: [(
            dom_actuator::DomSessionBindingV1,
            dom_actuator::DomXmrGraphSigningSharesV22,
        ); 2],
    ) -> Result<(), TestError> {
        let refund_point = dom_adaptor::SigningShareV1::from_be_bytes([42; 32])?
            .public_key()
            .to_compressed_bytes();
        Self::test_form_native_graphs_with_refund_point_v23(
            graphs,
            work,
            budget,
            c,
            d,
            signing_wallets,
            refund_point,
        )
        .map(|_| ())
    }

    pub(crate) fn test_form_native_graphs_with_refund_point_v23(
        graphs: &[Self; 2],
        work: [&std::path::Path; 2],
        budget: dom_scriptless_store::BudgetPolicyV1,
        c: [Option<(
            dom_scriptless_crypto::FrozenSharedOutputV1,
            dom_adaptor::VerifiedSharedOutputV1,
        )>; 2],
        d: [Option<(
            dom_scriptless_crypto::FrozenSharedOutputV1,
            dom_adaptor::VerifiedSharedOutputV1,
        )>; 2],
        signing_wallets: [(
            dom_actuator::DomSessionBindingV1,
            dom_actuator::DomXmrGraphSigningSharesV22,
        ); 2],
        refund_point: [u8; 33],
    ) -> Result<signing_v23::SignedNativeGraphFixtureV23, TestError> {
        let mut formed_graphs = Vec::new();
        let mut hashes = Vec::new();
        let mut sessions = Vec::new();
        for (actor, (c, d)) in c.into_iter().zip(d).enumerate() {
            let public = graphs[actor].assemble_peer_material_v22(&graphs[actor ^ 1].local)?;
            let formed = crate::production_relay_stage12::graph_v23::form_xmr_graph_templates_v23(
                &public,
                &graphs[actor].terms,
                &graphs[actor].policy,
                [
                    c.ok_or("missing native C proof")?,
                    d.ok_or("missing native D proof")?,
                ],
                10,
                refund_point,
            )?;
            formed.keys.require_route(graphs[actor].route_id)?;
            formed.keys.require_graph(&formed.templates)?;
            let templates = &formed.templates;
            let expected_pin = formed.keys.proposal()?.digest();
            for reopen in 0..2 {
                let chain = *graphs[actor].native.trusted_chain_id();
                let root = Arc::new(Dir::from_std_file(File::open(work[actor])?));
                let parent = dom_scriptless_store::ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
                    Arc::clone(&root),
                    "runtime-contracts",
                    budget.clone(),
                    chain,
                ).map_err(|error| format!("graph formation parent-open actor={actor} reopen={reopen}: {error}"))?;
                let cancelled = dom_scriptless_store::ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
                    root,
                    &format!(
                        "cancelled-contracts-{}",
                        graphs[actor].native.participant_index()
                    ),
                    budget.clone(),
                    chain,
                ).map_err(|error| format!("graph formation cancelled-open actor={actor} reopen={reopen}: {error}"))?;
                // Reopened, authenticated identities plus actual offer keys:
                // validate public signing scope without creating a nonce/grant.
                use crate::production_xmr_round_runtime_v12::{
                    require_xmr_recovery_signing_scope_v23,
                    ProductionXmrRecoveryRoundKindV12 as RoundKind,
                };
                use xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningStageV22 as Stage;
                let identities =
                    parent.transport_identity_references(templates.binding().session_id)?;
                let roster_for =
                    |stage: Stage,
                     swap_keys: bool,
                     swap_roles: bool|
                     -> Result<dom_adaptor::ParticipantRosterV1, TestError> {
                        let mut entries = Vec::new();
                        for identity in &identities {
                            let source = graphs
                                .iter()
                                .find(|graph| {
                                    graph.native.participant_id() == identity.participant_id()
                                })
                                .ok_or("missing authenticated graph identity")?;
                            let key_id = if swap_keys {
                                *identities
                                    .iter()
                                    .find(|other| {
                                        other.participant_id() != identity.participant_id()
                                    })
                                    .ok_or("missing peer identity")?
                                    .participant_id()
                            } else {
                                *identity.participant_id()
                            };
                            let mut role = source.native.role();
                            if swap_roles {
                                role = match role {
                                    dom_adaptor::DirectionV1::Initiator => {
                                        dom_adaptor::DirectionV1::Responder
                                    }
                                    dom_adaptor::DirectionV1::Responder => {
                                        dom_adaptor::DirectionV1::Initiator
                                    }
                                };
                            }
                            entries.push(dom_adaptor::ParticipantIdentityV1::new(
                                &chain,
                                identity.schnorr_public_key().clone(),
                                formed
                                    .keys
                                    .key(stage, key_id, formed.keys.template_hash(stage))?
                                    .clone(),
                                role,
                            )?);
                        }
                        entries.sort_by_key(|entry| *entry.participant_id());
                        Ok(dom_adaptor::ParticipantRosterV1::new(entries)?)
                    };
                let rounds = [
                    (RoundKind::Cancel, Stage::Cancel),
                    (RoundKind::RefundAdaptor, Stage::Refund),
                    (RoundKind::Compensation, Stage::Compensation),
                ];
                for (kind, stage) in rounds {
                    let roster = roster_for(stage, false, false)?;
                    require_xmr_recovery_signing_scope_v23(
                        &formed.keys,
                        templates,
                        &chain,
                        &roster,
                        kind,
                    )?;
                    for (_, wrong_stage) in rounds {
                        if wrong_stage != stage {
                            assert!(require_xmr_recovery_signing_scope_v23(
                                &formed.keys,
                                templates,
                                &chain,
                                &roster_for(wrong_stage, false, false)?,
                                kind,
                            )
                            .is_err());
                        }
                    }
                    for (swap_keys, swap_roles) in [(true, false), (false, true)] {
                        assert!(require_xmr_recovery_signing_scope_v23(
                            &formed.keys,
                            templates,
                            &chain,
                            &roster_for(stage, swap_keys, swap_roles)?,
                            kind,
                        )
                        .is_err());
                    }
                    let foreign_chain = dom_adaptor::TrustedChainIdV1::from_authenticated_genesis(
                        0x4455_6677,
                        &dom_core::Hash256::from_bytes([0xe1; 32]),
                    );
                    assert!(require_xmr_recovery_signing_scope_v23(
                        &formed.keys,
                        templates,
                        &foreign_chain,
                        &roster,
                        kind,
                    )
                    .is_err());
                }

                assert_eq!(
                    parent
                        .retain_xmr_graph_proposal_v23(
                            &cancelled,
                            chain,
                            graphs[actor].route_id,
                            &graphs[actor].terms,
                            templates,
                            &formed.keys,
                        )
                        .map_err(|error| format!(
                            "native graph pin actor={actor} reopen={reopen}: {error:?}"
                        ))?,
                    expected_pin,
                );
                assert_eq!(
                    parent
                        .freeze_xmr_graph_commit_context_v23(
                            chain,
                            graphs[actor].route_id,
                            templates.binding().session_id,
                        )
                        .map_err(|error| format!(
                            "graph formation freeze-context actor={actor} reopen={reopen}: {error}"
                        ))?,
                    expected_pin,
                );
                if reopen == 1 {
                    let (retained_templates, retained_keys) = parent
                        .reconstruct_retained_xmr_graph_v23(
                            chain,
                            graphs[actor].route_id,
                            templates.binding().session_id,
                        ).map_err(|error| format!("graph formation reconstruct actor={actor} reopen={reopen}: {error}"))?;
                    assert_eq!(retained_keys.proposal()?.digest(), expected_pin);
                    for (kind, stage) in rounds {
                        require_xmr_recovery_signing_scope_v23(
                            &retained_keys,
                            &retained_templates,
                            &chain,
                            &roster_for(stage, false, false)?,
                            kind,
                        )?;
                    }
                    assert!(parent
                        .reconstruct_retained_xmr_graph_v23(
                            chain,
                            [0; 32],
                            templates.binding().session_id,
                        )
                        .is_err());
                }
                assert!(parent
                    .retain_xmr_graph_proposal_v23(
                        &cancelled,
                        chain,
                        [0; 32],
                        &graphs[actor].terms,
                        templates,
                        &formed.keys,
                    )
                    .is_err());
                assert!(
                    !parent
                        .load_session(templates.binding().session_id)?
                        .irreversible()
                        .funding_authorized
                );
                assert!(parent
                    .resume_operational_signing_session(
                        chain,
                        templates.binding().session_id,
                        dom_adaptor::PurposeV1::Funding,
                    )
                    .is_err());
            }
            let mut local_hashes = Vec::new();
            for transaction in [
                templates.funding(),
                templates.claim(),
                templates.cancel(),
                templates.refund(),
                templates.compensation(),
            ] {
                assert_eq!(transaction.kernels.len(), 1);
                assert_eq!(transaction.kernels[0].excess_signature, [0; 65]);
                let (_, hash) = dom_adaptor::canonical_template_v1(transaction)?;
                assert!(!local_hashes.contains(&hash));
                local_hashes.push(hash);
            }
            assert_eq!(templates.cancel().kernels[0].lock_height, 100);
            assert_eq!(templates.refund().kernels[0].lock_height, 100);
            assert_eq!(templates.compensation().kernels[0].lock_height, 124);
            let session = templates.compensation_session_v23()?;
            assert_ne!(session, templates.binding().session_id);
            assert_ne!(
                session,
                dom_scriptless_crypto::xmr_ordinary_recovery_session_v12(
                    templates.binding(),
                    dom_scriptless_crypto::XmrOrdinaryRecoveryKindV12::Compensation,
                    local_hashes[4],
                )
            );
            hashes.push(local_hashes);
            sessions.push(session);
            formed_graphs.push(formed);
        }
        assert_eq!(hashes[0], hashes[1]);
        assert_eq!(sessions[0], sessions[1]);
        eprintln!("graph formation complete; entering authenticated commitment exchange");
        test_exchange_store_graph_commits_v23(graphs, work, budget.clone())?;
        eprintln!("graph commitment exchange complete; entering three native signing rounds");
        signing_v23::sign_three_real_edges(
            graphs,
            work,
            budget,
            signing_wallets,
            formed_graphs
                .try_into()
                .map_err(|_| "two formed graphs required")?,
        )
    }

    pub(crate) fn test_exchange_native_pair_v22(graphs: [Self; 2]) -> Result<(), TestError> {
        let left = graphs[0].assemble_peer_material_v22(&graphs[1].local)?;
        let right = graphs[1].assemble_peer_material_v22(&graphs[0].local)?;
        assert!(graphs[0]
            .assemble_peer_material_v22(&graphs[0].local)
            .is_err());
        assert_eq!(
            left.signing_material.packets(),
            right.signing_material.packets()
        );
        let canonical_packets = if graphs[0].native.participant_index() == 0 {
            [graphs[0].local.as_slice(), graphs[1].local.as_slice()]
        } else {
            [graphs[1].local.as_slice(), graphs[0].local.as_slice()]
        };
        assert_eq!(left.signing_material.packets(), canonical_packets);
        assert_eq!(left.funding_fee_noms, right.funding_fee_noms);
        assert!(left.funding_fee_noms > 0);
        assert_eq!(
            left.funding_inputs
                .iter()
                .map(|input| *input.commitment.as_bytes())
                .collect::<Vec<_>>(),
            right
                .funding_inputs
                .iter()
                .map(|input| *input.commitment.as_bytes())
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            left.funding_change
                .iter()
                .map(|output| *output.commitment.as_bytes())
                .collect::<Vec<_>>(),
            right
                .funding_change
                .iter()
                .map(|output| *output.commitment.as_bytes())
                .collect::<Vec<_>>(),
        );
        let policy = graphs[0].policy.policy();
        let payouts = [
            policy.claim_principal_commitment,
            policy.claim_change_commitment,
            policy.refund_recipient_commitment,
            policy.compensation_recipient_commitment,
        ];
        for (index, commitment) in payouts.into_iter().enumerate() {
            assert_eq!(left.payouts[index].commitment.as_bytes(), &commitment);
            assert_eq!(right.payouts[index].commitment.as_bytes(), &commitment);
        }
        for index in 0..2 {
            assert_eq!(
                left.payout_value_proofs[index].statement.to_bytes(),
                right.payout_value_proofs[index].statement.to_bytes()
            );
            assert_eq!(
                left.payout_value_proofs[index].proof.to_bytes(),
                right.payout_value_proofs[index].proof.to_bytes()
            );
        }
        for index in 0..5 {
            assert_eq!(left.kernels[index].excess, right.kernels[index].excess);
            assert_eq!(left.kernels[index].offset, right.kernels[index].offset);
        }
        let temp = tempfile::TempDir::new()?;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
        let parent = Arc::new(Dir::from_std_file(File::open(temp.path())?));
        let mut references = Vec::new();
        for (index, graph) in graphs.iter().enumerate() {
            let identity = ContractsTransportIdentityStoreV1::create_production(
                Arc::clone(&parent),
                &format!("identity-{index}"),
                &passphrase()?,
            )?;
            references.push(
                identity
                    .reference()
                    .bind_session_participant(*graph.native.participant_id())?,
            );
        }
        let configs = [0xd1, 0xd2].map(|tag| {
            RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([tag; 32]).unwrap(), 32).unwrap()
        });
        let roots = [temp.path().join("relay-0"), temp.path().join("relay-1")];
        for index in 0..2 {
            drop(ProductionRelayV1::create(&roots[index], configs[index])?);
        }
        for round in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let address = listener.local_addr()?;
            let remote_parent = Arc::clone(&parent);
            let remote_root = roots[1].clone();
            let remote_local = references[1].clone();
            let remote_peer = references[0].clone();
            let remote_graph = copy_context(&graphs[1])?;
            let expected = graphs[0].local.clone();
            let responder = thread::spawn(move || -> Result<(), TestError> {
                let identity = ContractsTransportIdentityStoreV1::open_production(
                    remote_parent,
                    "identity-1",
                    &passphrase()?,
                )?;
                let mut relay = ProductionRelayV1::open(&remote_root, configs[1])?;
                let (stream, _) = listener.accept()?;
                let result = session(
                    NoiseRoleV1::Responder,
                    remote_graph,
                    remote_local,
                    remote_peer,
                    configs[1].database_id(),
                    configs[0].database_id(),
                )?
                .exchange(&identity, &mut relay, stream);
                if round == 2 {
                    assert_eq!(
                        result.unwrap_err(),
                        ProductionNoiseRelayErrorV1::ProtocolRefused
                    );
                } else {
                    let report = result?;
                    assert_eq!(report.graph_candidate_v22.unwrap().bytes(), expected);
                    assert_eq!((report.pages_sent, report.pages_received), (2, 2));
                    assert_eq!((report.envelopes_sent, report.envelopes_received), (0, 0));
                }
                Ok(())
            });
            let identity = ContractsTransportIdentityStoreV1::open_production(
                Arc::clone(&parent),
                "identity-0",
                &passphrase()?,
            )?;
            let mut local_graph = copy_context(&graphs[0])?;
            if round == 2 {
                // Simulate a malicious peer after local validation: corrupt
                // the first PoP, retaining valid framing and Hello scope.
                local_graph.local[365] ^= 0x80;
            }
            let mut relay = ProductionRelayV1::open(&roots[0], configs[0])?;
            let result = session(
                NoiseRoleV1::Initiator,
                local_graph,
                references[0].clone(),
                references[1].clone(),
                configs[0].database_id(),
                configs[1].database_id(),
            )?
            .exchange(&identity, &mut relay, TcpStream::connect(address)?);
            if round == 2 {
                assert_eq!(
                    result.unwrap_err(),
                    ProductionNoiseRelayErrorV1::PeerRefused
                );
            } else {
                let report = result?;
                assert_eq!(report.graph_candidate_v22.unwrap().bytes(), graphs[1].local);
                assert_eq!((report.pages_sent, report.pages_received), (2, 2));
                assert_eq!((report.envelopes_sent, report.envelopes_received), (0, 0));
            }
            responder
                .join()
                .map_err(|_| io::Error::other("native graph responder panicked"))??;
        }
        Ok(())
    }
}

/// Two real identity owners consume Store-issued requests. Reopening between
/// messages exercises durable partial progress; no private identity or kernel
/// signing scalar is read by the fixture.
fn test_exchange_store_graph_commits_v23(
    graphs: &[ProductionNoiseGraphOfferV22; 2],
    work: [&std::path::Path; 2],
    budget: dom_scriptless_store::BudgetPolicyV1,
) -> Result<(), TestError> {
    use dom_scriptless_store::{ContractsSessionStoreV1, SessionPhaseV1};
    let chain = *graphs[0].native.trusted_chain_id();
    let session = *graphs[0].native.session_id();
    let route = graphs[0].route_id;
    assert_eq!(
        graphs[1].native.trusted_chain_id().as_bytes(),
        chain.as_bytes()
    );
    assert_eq!(graphs[1].native.session_id(), &session);
    assert_eq!(graphs[1].route_id, route);
    let open = |actor: usize, stage: &str| -> Result<ContractsSessionStoreV1, TestError> {
        Ok(
            ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
                Arc::new(Dir::from_std_file(File::open(work[actor]).map_err(
                    |error| format!("graph commit {stage} root-open actor={actor}: {error}"),
                )?)),
                "runtime-contracts",
                budget.clone(),
                chain,
            )
            .map_err(|error| format!("graph commit {stage} store-open actor={actor}: {error}"))?,
        )
    };
    let mut delivered = Vec::new();
    for (position, role) in [
        dom_adaptor::DirectionV1::Initiator,
        dom_adaptor::DirectionV1::Responder,
    ]
    .into_iter()
    .enumerate()
    {
        let sender = graphs
            .iter()
            .position(|graph| graph.native.role() == role)
            .ok_or("missing graph commitment sender")?;
        let peer = sender ^ 1;
        let stores = [open(0, "before-turn")?, open(1, "before-turn")?];
        for store in &stores {
            assert_eq!(
                store.load_session(session)?.revision(),
                17 + position as u64
            );
        }
        assert!(stores[peer]
            .prepare_xmr_graph_commit_dsc1_signing_request_v23(chain, route, session,)
            .map_err(|error| format!("graph commit peer/final-request: {error}"))?
            .is_none());
        let identity = ContractsTransportIdentityStoreV1::open_production(
            Arc::new(Dir::from_std_file(File::open(
                work[sender].join("identity-parent"),
            )?)),
            "identity",
            &ContractsIdentityPassphraseV1::new(b"test-passphrase-v13".to_vec())?,
        )?;
        let request = stores[sender]
            .prepare_xmr_graph_commit_dsc1_signing_request_v23(chain, route, session)
            .map_err(|error| {
                format!("graph commit prepare actor={sender} position={position}: {error}")
            })?
            .ok_or("missing local graph commitment request")?;
        let committed = identity
            .sign_and_commit_store_prepared_dsc1(&stores[sender], request)
            .map_err(|error| {
                format!(
                    "graph commit consume-sign-commit actor={sender} position={position}: {error}"
                )
            })?;
        let bytes = committed.signed_bytes().to_vec();
        let parsed = dom_scriptless_transport::SignedMessageV1::decode_exact(&bytes)?;
        assert_eq!(
            parsed.unsigned().kind(),
            dom_scriptless_transport::MessageTypeV1::XmrGraphTemplateCommitV22
        );
        assert_eq!(parsed.unsigned().session_id(), &session);
        assert_eq!(
            parsed.unsigned().sender_id(),
            graphs[sender].native.participant_id()
        );
        let before = stores[peer].load_session(session)?;
        assert!(stores[peer]
            .accept_transport_message_derived(&bytes)
            .is_err());
        assert_eq!(
            stores[peer].load_session(session)?.as_bytes(),
            before.as_bytes()
        );
        stores[peer]
            .accept_prepared_xmr_graph_commit_transport_message_v23(chain, route, session, &bytes)
            .map_err(|error| {
                format!("graph commit peer-accept actor={peer} position={position}: {error}")
            })?;
        for store in &stores {
            let head = store.load_session(session)?;
            assert_eq!(head.revision(), 18 + position as u64);
            assert_eq!(head.phase(), SessionPhaseV1::TemplatesCommitted);
            assert!(!head.irreversible().funding_authorized);
            assert!(!head.irreversible().any_signing_share_sent);
            assert!(!head.irreversible().adaptor_secret_exposed);
        }
        eprintln!("graph commitment position={position} accepted by both stores");
        delivered.push(bytes);
        drop(identity);
        drop(stores);
        // Recovery reauthenticates the actual request/consumption/message chain.
        for actor in 0..2 {
            let reopened = open(actor, "reopen-after-turn")?;
            let before = reopened.load_session(session)?;
            for bytes in &delivered {
                reopened
                    .accept_prepared_xmr_graph_commit_transport_message_v23(
                        chain, route, session, bytes,
                    )
                    .map_err(|error| {
                        format!("graph commit replay actor={actor} position={position}: {error}")
                    })?;
            }
            assert_eq!(
                reopened.load_session(session)?.as_bytes(),
                before.as_bytes()
            );
            assert!(
                reopened
                    .resume_operational_signing_session(
                        chain,
                        session,
                        dom_adaptor::PurposeV1::Funding,
                    )
                    .is_err()
            );
        }
    }
    for actor in 0..2 {
        let store = open(actor, "final-reopen")?;
        assert!(store
            .prepare_xmr_graph_commit_dsc1_signing_request_v23(chain, route, session,)?
            .is_none());
        assert_eq!(store.load_session(session)?.revision(), 19);
        assert!(
            !store
                .load_session(session)?
                .irreversible()
                .funding_authorized
        );
    }
    Ok(())
}
