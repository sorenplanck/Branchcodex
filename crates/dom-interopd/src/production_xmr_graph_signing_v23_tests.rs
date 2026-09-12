//! Reuses the two real wallets, C/D proofs and committed graph from the parent
//! fixture. No signing scalar, fabricated transcript or replacement BP proof.
use super::*;
use crate::production_dom_claim_driver_v12::{
    prepare_next_xmr_graph_recovery_edge_v23, ProductionDomClaimProgressV12,
};
use crate::production_dom_vaults_v12::{
    ProductionDomVaultPurposeV12, ProductionXmrGraphVaultKeyV23,
};
use crate::production_relay_stage12::graph_v23::PreparedXmrGraphV23;
use crate::production_xmr_round_runtime_v12::{
    produce_completed_xmr_ordinary_round_v12, ProductionCompletedXmrRefundRoundV12,
};
use dom_actuator::{
    participant_retained_vault_signer_v12, DomSessionBindingV1, DomXmrGraphSigningSharesV22,
};
use dom_adaptor::{canonical_template_v1, AcceptedSigningSessionV1};
use dom_scriptless_crypto::XmrOrdinaryRecoveryKindV12;
use dom_scriptless_store::{
    AcceptedContractsSigningSessionV1, ContractsSessionStoreV1, SessionRecordV1,
    XmrGraphRecoverySigningEdgeV23 as Edge,
};
use std::rc::Rc;

/// One fully audited prefix, consumed once at the next signing turn. This is
/// local to this serial fixture, not a Store cache or a persisted authority.
struct AuditedNativeGraphTurnV23 {
    accepted: AcceptedContractsSigningSessionV1,
    head: SessionRecordV1,
}

impl AuditedNativeGraphTurnV23 {
    fn read(
        store: &ContractsSessionStoreV1,
        target: [u8; 32],
        edge: Edge,
        prefix: usize,
    ) -> Result<Self, TestError> {
        // Keep the production full transport, graph ancestry and semantic
        // replay audit for both actors at EVERY accepted prefix.
        let accepted = store.resume_xmr_graph_signing_session_v23(target, edge)?;
        let head = store.load_session(target)?;
        assert_eq!(accepted.session_id(), &target);
        assert_eq!(accepted.accepted_signing_messages().count(), prefix);
        assert!(!head.irreversible().funding_authorized);
        assert!(!head.irreversible().adaptor_secret_exposed);
        assert_eq!(head.irreversible().any_signing_share_sent, prefix >= 5);
        Ok(Self { accepted, head })
    }

    fn consume(
        self,
        store: &ContractsSessionStoreV1,
        target: [u8; 32],
        prefix: usize,
    ) -> Result<AcceptedContractsSigningSessionV1, TestError> {
        assert_eq!(self.accepted.session_id(), &target);
        assert_eq!(self.accepted.accepted_signing_messages().count(), prefix);
        assert_eq!(store.load_session(target)?.as_bytes(), self.head.as_bytes());
        Ok(self.accepted)
    }
}

/// Owners retained across the signing/reopen boundary for native lifecycle tests.
/// This component fixture does not stand in for daemon F6 authentication.
pub(crate) struct SignedNativeGraphFixtureV23 {
    pub(crate) stores: [Rc<ContractsSessionStoreV1>; 2],
    pub(crate) chain: dom_adaptor::TrustedChainIdV1,
    pub(crate) budget: dom_scriptless_store::BudgetPolicyV1,
    pub(crate) produced: [xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12; 2],
    pub(crate) wallets: [(DomSessionBindingV1, DomXmrGraphSigningSharesV22); 2],
    pub(crate) bindings: [[DomSessionBindingV1; 3]; 2],
    pub(crate) keys: [xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningKeysV22; 2],
}

pub(super) fn sign_three_real_edges(
    offers: &[ProductionNoiseGraphOfferV22; 2],
    work: [&std::path::Path; 2],
    budget: dom_scriptless_store::BudgetPolicyV1,
    wallets: [(DomSessionBindingV1, DomXmrGraphSigningSharesV22); 2],
    formed: [PreparedXmrGraphV23; 2],
) -> Result<SignedNativeGraphFixtureV23, TestError> {
    let started = std::time::Instant::now();
    let chain = *offers[0].native.trusted_chain_id();
    let parent = *offers[0].native.session_id();
    let route = offers[0].route_id;
    let open_store = |actor, stage: &str| -> Result<Rc<ContractsSessionStoreV1>, TestError> {
        Ok(Rc::new(
            ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
                Arc::new(Dir::from_std_file(File::open(work[actor]).map_err(
                    |error| format!("graph signing root-open actor={actor}: {error}"),
                )?)),
                "runtime-contracts",
                budget.clone(),
                chain,
            )
            .map_err(|error| format!("graph signing {stage} store-open actor={actor}: {error}"))?,
        ))
    };
    let stores = [open_store(0, "initial")?, open_store(1, "initial")?];
    let mut identities = Vec::new();
    for actor in 0..2 {
        identities.push(ContractsTransportIdentityStoreV1::open_production(
            Arc::new(Dir::from_std_file(File::open(
                work[actor].join("identity-parent"),
            )?)),
            "identity",
            &ContractsIdentityPassphraseV1::new(b"test-passphrase-v13".to_vec())?,
        )?);
    }
    let edges = [Edge::Cancel, Edge::RefundAdaptor, Edge::Compensation];
    let purposes = [
        ProductionDomVaultPurposeV12::XmrCancel,
        ProductionDomVaultPurposeV12::XmrRefundU,
        ProductionDomVaultPurposeV12::XmrCompensation,
    ];
    let mut bindings = Vec::new();
    let mut signers = Vec::new();
    let mut retained_wallets = Vec::new();
    // These constants encrypt only test vaults. Every excess share still comes
    // from its original encrypted wallet and independently reconstructed C/D.
    let unlocks = [
        zeroize::Zeroizing::new([0xc1; 32]),
        zeroize::Zeroizing::new([0xc2; 32]),
    ];
    for (actor, (binding, mut shares)) in wallets.into_iter().enumerate() {
        let graph = &formed[actor];
        let cancel_hash = canonical_template_v1(graph.templates.cancel())?.1;
        let compensation_hash = canonical_template_v1(graph.templates.compensation())?.1;
        let native_bindings = [
            binding
                .for_xmr_ordinary_recovery_v22(
                    graph.templates.binding(),
                    XmrOrdinaryRecoveryKindV12::Cancel,
                    cancel_hash,
                )
                .map_err(|error| {
                    format!("graph signing cancel-scope/share actor={actor}: {error}")
                })?,
            binding,
            binding.for_xmr_compensation_v23(
                graph.templates.binding(),
                graph.templates.policy(),
                compensation_hash,
            )?,
        ];
        for (index, edge) in edges.into_iter().enumerate() {
            stores[actor]
                .retain_xmr_graph_signing_origin_v23(chain, route, parent, edge)
                .map_err(|error| {
                    format!("graph signing retain-origin actor={actor} edge={index}: {error}")
                })?;
            stores[actor]
                .prepare_xmr_graph_signing_session_v23(native_bindings[index].session_id(), edge)
                .map_err(|error| {
                    format!("graph signing prepare-binding actor={actor} edge={index}: {error}")
                })?;
            stores[actor]
                .bind_local_transport_signer(
                    native_bindings[index].session_id(),
                    *identities[actor].reference().key_reference(),
                )
                .map_err(|error| {
                    format!("graph signing bind-local actor={actor} edge={index}: {error}")
                })?;
        }
        let extracted = [
            shares.take_ordinary_share_v22(
                &stores[actor],
                graph.templates.binding(),
                XmrOrdinaryRecoveryKindV12::Cancel,
                cancel_hash,
            )?,
            shares
                .take_refund_adaptor_share_v23(&stores[actor], &graph.templates)
                .map_err(|error| format!("graph signing refund-share actor={actor}: {error}"))?,
            shares
                .take_compensation_share_v23(&stores[actor], &graph.templates)
                .map_err(|error| {
                    format!("graph signing compensation-share actor={actor}: {error}")
                })?,
        ];
        let mut actor_signers = Vec::new();
        for (index, share) in extracted.into_iter().enumerate() {
            let vault = ProductionXmrGraphVaultKeyV23::retain(&unlocks[actor])
                .mount(
                    Arc::new(Dir::from_std_file(File::open(work[actor])?)),
                    budget.clone(),
                    true,
                )
                .provision(&stores[actor], native_bindings[index], purposes[index])
                .map_err(|error| {
                    format!("graph signing provision-vault actor={actor} edge={index}: {error}")
                })?;
            assert_eq!(
                stores[actor]
                    .prepare_xmr_graph_resource_v23(
                        native_bindings[index].session_id(),
                        edges[index],
                        dom_scriptless_store::XmrGraphResourceKindV23::NonceVault,
                    )
                    .map_err(|error| format!(
                        "graph signing vault-ready actor={actor} edge={index}: {error}"
                    ))?
                    .state(),
                dom_scriptless_store::XmrGraphResourceStateV23::Ready,
            );
            actor_signers.push(participant_retained_vault_signer_v12(
                vault,
                Rc::clone(&stores[actor]),
                native_bindings[index],
                chain,
                share,
            )?);
        }
        eprintln!("graph signing actor={actor} native origins, bindings and vault signers ready");
        retained_wallets.push((binding, shares));
        bindings.push(native_bindings);
        signers.push(actor_signers);
    }
    let mut messages: [Vec<Vec<u8>>; 3] = std::array::from_fn(|_| Vec::new());
    for (index, edge) in edges.into_iter().enumerate() {
        let round_started = std::time::Instant::now();
        let target = bindings[0][index].session_id();
        assert_eq!(target, bindings[1][index].session_id());
        let ingress = [
            stores[0]
                .prepare_xmr_graph_signing_ingress_v23(target, edge)
                .map_err(|error| {
                    format!("graph signing prepare-ingress actor=0 edge={index}: {error}")
                })?,
            stores[1]
                .prepare_xmr_graph_signing_ingress_v23(target, edge)
                .map_err(|error| {
                    format!("graph signing prepare-ingress actor=1 edge={index}: {error}")
                })?,
        ];
        let mut turns = [None, None];
        let mut audited_prefixes = [[0u8; 7]; 2];
        for actor in 0..2 {
            turns[actor] = Some(
                AuditedNativeGraphTurnV23::read(&stores[actor], target, edge, 0).map_err(
                    |error| {
                        format!("graph signing initial-audit actor={actor} edge={index}: {error}")
                    },
                )?,
            );
            audited_prefixes[actor][0] += 1;
        }
        let roster: [[u8; 32]; 2] = std::array::from_fn(|position| {
            *turns[0].as_ref().unwrap().accepted.roster().entries()[position].participant_id()
        });
        for actor in 0..2 {
            let entries = turns[actor].as_ref().unwrap().accepted.roster().entries();
            assert_eq!(entries.len(), 2);
            for (entry, participant) in entries.iter().zip(roster) {
                assert_eq!(entry.participant_id(), &participant);
            }
        }
        for position in 0..6 {
            let turn_started = std::time::Instant::now();
            let sender_id = &roster[position % 2];
            let sender = bindings
                .iter()
                .position(|entry| &entry[index].participant().participant_id() == sender_id)
                .ok_or("missing wallet signer")?;
            let peer = sender ^ 1;
            // Nothing mutates either Store between the preceding two audits
            // and this consume. Reuse that exact prefix instead of performing
            // two more full audits merely to select a sender and read it again.
            // The production signer/request/ingress gates still reauthenticate
            // their own authorities; all stale handles are discarded below.
            let accepted = turns[sender]
                .take()
                .ok_or("missing fully audited native graph turn")?
                .consume(&stores[sender], target, position)?;
            drop(turns[peer].take());
            let request = match prepare_next_xmr_graph_recovery_edge_v23(
                &stores[sender],
                bindings[sender][index],
                chain,
                &mut signers[sender][index],
                accepted,
                edge,
            ).map_err(|error| format!("graph signing prepare-request actor={sender} edge={index} position={position}: {error}"))? {
                ProductionDomClaimProgressV12::Prepared(request) => request,
                _ => return Err("native signing turn produced no request".into()),
            };
            assert_eq!(request.message_type(), 0x0c + (position / 2) as u8);
            let committed =
                identities[sender].sign_and_commit_store_prepared_dsc1(&stores[sender], request)
                    .map_err(|error| format!("graph signing consume-sign-commit actor={sender} edge={index} position={position}: {error}"))?;
            let bytes = committed.signed_bytes().to_vec();
            let peer_before = stores[peer].load_session(target)?;
            // Generic unseen ingress stays closed even after native admission.
            assert!(stores[peer]
                .accept_transport_message_derived(&bytes)
                .is_err());
            assert_eq!(
                stores[peer].load_session(target)?.as_bytes(),
                peer_before.as_bytes()
            );
            stores[peer].accept_xmr_graph_signing_ingress_v23(&ingress[peer], &bytes)
                .map_err(|error| format!("graph signing peer-accept actor={peer} edge={index} position={position}: {error}"))?;
            for actor in 0..2 {
                assert!(turns[actor].is_none());
                turns[actor] = Some(AuditedNativeGraphTurnV23::read(
                    &stores[actor], target, edge, position + 1,
                ).map_err(|error| format!("graph signing audit-accepted actor={actor} edge={index} position={position}: {error}"))?);
                audited_prefixes[actor][position + 1] += 1;
            }
            messages[index].push(bytes);
            eprintln!("graph signing edge={index} position={position} accepted and audited by both stores; turn={:?}", turn_started.elapsed());
        }
        assert_eq!(
            audited_prefixes, [[1; 7]; 2],
            "every prefix must receive a full independent audit from each Store"
        );
        drop(turns);
        eprintln!(
            "graph signing edge={index} completed with 14 full prefix audits after {:?}",
            round_started.elapsed()
        );
    }
    eprintln!(
        "graph signing all three six-envelope rounds accepted after {:?}",
        started.elapsed()
    );
    // Reconstruct both plain signatures and the U adaptor pre-signature from
    // the actual six-envelope journals, then complete the native graph verifier.
    // No U secret is adapted and no funding authority is requested.
    let mut produced = Vec::new();
    let mut retained_keys = Vec::new();
    for (actor, graph) in formed.into_iter().enumerate() {
        let cancel_session = stores[actor]
            .resume_xmr_graph_signing_session_v23(bindings[actor][0].session_id(), Edge::Cancel)
            .map_err(|error| format!("graph completion cancel-session actor={actor}: {error}"))?;
        let refund_session = stores[actor]
            .resume_xmr_graph_signing_session_v23(parent, Edge::RefundAdaptor)
            .map_err(|error| format!("graph completion refund-session actor={actor}: {error}"))?;
        let compensation_session = stores[actor]
            .resume_xmr_graph_signing_session_v23(
                bindings[actor][2].session_id(),
                Edge::Compensation,
            )
            .map_err(|error| {
                format!("graph completion compensation-session actor={actor}: {error}")
            })?;
        let cancel = produce_completed_xmr_ordinary_round_v12(
            &cancel_session,
            &graph.templates,
            &graph.keys,
            XmrOrdinaryRecoveryKindV12::Cancel,
        )
        .map_err(|error| format!("graph completion cancel-signature actor={actor}: {error}"))?;
        let compensation = produce_completed_xmr_ordinary_round_v12(
            &compensation_session,
            &graph.templates,
            &graph.keys,
            XmrOrdinaryRecoveryKindV12::Compensation,
        )
        .map_err(|error| {
            format!("graph completion compensation-signature actor={actor}: {error}")
        })?;
        let refund = ProductionCompletedXmrRefundRoundV12::from_store_session(
            &refund_session,
            &graph.templates,
            &graph.keys,
        )
        .map_err(|error| format!("graph completion refund-presignature actor={actor}: {error}"))?;
        produced.push(
            refund
                .complete_graph(graph.templates, cancel, compensation)
                .map_err(|error| format!("graph completion verify actor={actor}: {error}"))?,
        );
        retained_keys.push(graph.keys);
        eprintln!("graph completion actor={actor} verified");
    }
    drop(signers);
    drop(identities);
    drop(stores);
    // Reopen the exact encrypted vaults without creation, then reissue native
    // handles and replay all 18 signed bytes against unchanged durable heads.
    let mut reopened = Vec::new();
    for actor in 0..2 {
        let reopen_started = std::time::Instant::now();
        let store = open_store(actor, "final-reopen")?;
        eprintln!(
            "graph signing durable reopen actor={actor} opened after {:?}",
            reopen_started.elapsed()
        );
        for (index, edge) in edges.into_iter().enumerate() {
            let replay_started = std::time::Instant::now();
            let target = bindings[actor][index].session_id();
            let permit = store
                .prepare_xmr_graph_resource_v23(
                    target,
                    edge,
                    dom_scriptless_store::XmrGraphResourceKindV23::NonceVault,
                )
                .map_err(|error| {
                    format!("graph signing reopen-ready actor={actor} edge={index}: {error}")
                })?;
            assert_eq!(
                permit.state(),
                dom_scriptless_store::XmrGraphResourceStateV23::Ready
            );
            let vault = ProductionXmrGraphVaultKeyV23::retain(&unlocks[actor])
                .mount(
                    Arc::new(Dir::from_std_file(File::open(work[actor])?)),
                    budget.clone(),
                    false,
                )
                .provision(&store, bindings[actor][index], purposes[index])
                .map_err(|error| {
                    format!("graph signing reopen-vault actor={actor} edge={index}: {error}")
                })?;
            let before = store.load_session(target)?;
            let ingress = store
                .prepare_xmr_graph_signing_ingress_v23(target, edge)
                .map_err(|error| {
                    format!("graph signing reopen-ingress actor={actor} edge={index}: {error}")
                })?;
            for bytes in &messages[index] {
                store
                    .accept_xmr_graph_signing_ingress_v23(&ingress, bytes)
                    .map_err(|error| {
                        format!("graph signing reopen-replay actor={actor} edge={index}: {error}")
                    })?;
            }
            assert_eq!(store.load_session(target)?.as_bytes(), before.as_bytes());
            let accepted = store
                .resume_xmr_graph_signing_session_v23(target, edge)
                .map_err(|error| {
                    format!("graph signing reopen-accepted actor={actor} edge={index}: {error}")
                })?;
            assert_eq!(accepted.accepted_signing_messages().count(), 6);
            assert!(!before.irreversible().funding_authorized);
            assert!(before.irreversible().any_signing_share_sent);
            assert!(!before.irreversible().adaptor_secret_exposed);
            drop(vault);
            eprintln!(
                "graph signing durable replay actor={actor} edge={index} verified after {:?}",
                replay_started.elapsed()
            );
        }
        reopened.push(store);
    }
    Ok(SignedNativeGraphFixtureV23 {
        chain,
        budget,
        keys: retained_keys
            .try_into()
            .map_err(|_| "expected two graph key sets")?,
        stores: reopened
            .try_into()
            .map_err(|_| "expected two reopened stores")?,
        produced: produced
            .try_into()
            .map_err(|_| "expected two verified graphs")?,
        wallets: retained_wallets
            .try_into()
            .map_err(|_| "expected two retained wallets")?,
        bindings: bindings
            .try_into()
            .map_err(|_| "expected two binding sets")?,
    })
}
