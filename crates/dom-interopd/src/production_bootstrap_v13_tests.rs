//! Native encrypted custody + the actual ceremony executor. No live RPC.
use super::*;
use crate::production_inputs::{ProductionRosterLegV1, ProductionRosterMemberV1};
use deployment_registry::{AuthoritySetV1, RegistrySignatureV1, SignedRegistryV1};
use std::os::unix::fs::PermissionsExt;

#[cfg(target_os = "linux")]
#[path = "production_xmr_native_bootstrap_path_v24_tests.rs"]
mod bootstrap_path_v24;

#[cfg(target_os = "linux")]
#[path = "production_xmr_native_f6_source_fixture_v25_tests.rs"]
pub(crate) mod f6_source_fixture_v25;

#[path = "production_xmr_native_proof_timing_v25_tests.rs"]
mod native_proof_timing_v25;

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn directory(path: &Path) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}
fn policy() -> BudgetPolicyV1 {
    use dom_scriptless_store::BUDGET_POLICY_LEN;
    let mut bytes = [0; BUDGET_POLICY_LEN];
    bytes[..8].copy_from_slice(b"DOMNVBP1");
    bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
    bytes[10] = BudgetPolicyProfileV1::ProductionRatified as u8;
    bytes[11] = 1;
    bytes[16..48].fill(13);
    for (offset, value) in [
        (48, 100_u64),
        (56, 50),
        (72, 25),
        (80, 3600),
        (88, 60),
        (96, 86400),
        (104, 1),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
    let digest = dom_scriptless_crypto::authoritative_storage_hash_v1(
        dom_scriptless_crypto::StorageHashDomainV1::BudgetPolicy,
        &bytes[..112],
    );
    bytes[112..].copy_from_slice(&digest);
    BudgetPolicyV1::from_bytes(&bytes).unwrap()
}
struct Fixture {
    _root: tempfile::TempDir,
    work: [PathBuf; 2],
    plan: [PathBuf; 2],
    credentials: [Vec<u8>; 2],
}
fn fixture() -> Fixture {
    fixture_with_xmr(false)
}

#[path = "production_bootstrap_xmr_cancelled_v22_tests.rs"]
mod xmr_cancelled_tests;
#[cfg(target_os = "linux")]
#[path = "production_xmr_native_coldstart_v23_tests.rs"]
pub(crate) mod xmr_coldstart_v23;
#[path = "production_xmr_graph_replay_v23_tests.rs"]
mod xmr_graph_replay_tests;
#[path = "production_xmr_graph_wallet_v22_tests.rs"]
mod xmr_graph_wallet_tests;

fn fixture_with_xmr(xmr: bool) -> Fixture {
    fixture_with_xmr_context_v23(xmr, None)
}

fn fixture_with_xmr_context_v23(
    xmr: bool,
    native: Option<&xmr_graph_wallet_tests::native_custody_v23::NativeXmrSecretsFixtureV23>,
) -> Fixture {
    fixture_with_registry_configuration_v23(xmr, |manifest, terms| {
        if let Some(native) = native {
            assert!(xmr);
            native.configure_registry(manifest, terms).unwrap();
        }
    })
}

fn fixture_with_registry_configuration_v23(
    xmr: bool,
    configure: impl FnOnce(&mut deployment_registry::RegistryManifestV1, [&mut SettlementTermsV1; 2]),
) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let secp = SecpContext::new(&[13; 32]);
    let (previous, mut up, mut down) = crate::route_time_test_common::mainnet_registry_and_terms();
    let mut manifest = previous.manifest().clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    manifest.valid_from = now - 60;
    manifest.expires_at = now + 3600;
    // A new scenario may explicitly negotiate a different bounded lifetime.
    // Apply it before signing, never rewrite the signed registry afterwards.
    configure(&mut manifest, [&mut up, &mut down]);
    let key = secp.xonly_public_key(&[91; 32]).unwrap();
    let authorities = AuthoritySetV1::new(1, vec![key]).unwrap();
    let digest = manifest.manifest_digest().unwrap();
    let (signature, _) = secp.sign_bip340(&[91; 32], &digest, &[92; 32]).unwrap();
    let signed = SignedRegistryV1::new(
        &manifest,
        vec![RegistrySignatureV1 {
            signer_index: 0,
            signature,
        }],
    )
    .unwrap();
    write(
        &root.path().join("registry.signed.bin"),
        &signed.canonical_bytes().unwrap(),
    );
    let registry_path = root.path().join("registry.sqlite");
    let mut store = RegistryStoreV1::create(&registry_path).unwrap();
    store
        .install(
            &signed,
            &authorities,
            &secp,
            RegistryValidationPolicyV1 {
                now_seconds: now,
                expected_network_id: manifest.network_id,
                minimum_epoch: manifest.epoch,
            },
        )
        .unwrap();
    drop(store);
    let authority_path = root.path().join("authorities.bin");
    let bundle = ProductionAuthorityBundleV1::new(
        authorities.clone(),
        AuthoritySetV1::new(1, vec![secp.xonly_public_key(&[93; 32]).unwrap()]).unwrap(),
        AuthoritySetV1::new(1, vec![secp.xonly_public_key(&[94; 32]).unwrap()]).unwrap(),
    )
    .unwrap();
    write(&authority_path, &bundle.canonical_bytes().unwrap());
    let work = [root.path().join("alice"), root.path().join("bob")];
    let mut participants = Vec::new();
    let mut identities = Vec::new();
    for path in &work {
        directory(path);
        let parent = path.join("identity-parent");
        directory(&parent);
        let identity = ContractsTransportIdentityStoreV1::create_production(
            private_directory(&parent).unwrap(),
            "identity",
            &ContractsIdentityPassphraseV1::new(b"test-passphrase-v13".to_vec()).unwrap(),
        )
        .unwrap();
        let mut body = manifest.dom.chain_id.0.to_vec();
        body.extend_from_slice(identity.reference().schnorr_public_key());
        participants.push(ParticipantId(
            *dom_crypto::blake2b_256_tagged(dom_adaptor::DomainTag::Participant.as_str(), &body)
                .as_bytes(),
        ));
        identities.push(parent.join("identity"));
        drop(identity);
    }
    let mut sorted = [participants[0], participants[1]];
    sorted.sort();
    for terms in [&mut up, &mut down] {
        terms.roster = sorted;
        terms.dom_leg.beneficiary = participants[1];
        terms.dom_leg.refund_to = participants[0];
        terms.counterparty_leg.beneficiary = participants[0];
        terms.counterparty_leg.refund_to = participants[1];
    }
    let terms_paths = [root.path().join("up.terms"), root.path().join("down.terms")];
    let mut terms = [up, down];
    let xmr_policy_files = if xmr {
        Some(xmr_cancelled_tests::configure_terms(
            root.path(),
            &mut terms,
        ))
    } else {
        None
    };
    for l in 0..2 {
        write(&terms_paths[l], &terms[l].canonical_bytes().unwrap());
    }
    let relay = [[[21; 32], [22; 32]], [[23; 32], [24; 32]]];
    let mut legs = Vec::new();
    for l in 0..2 {
        let mut members = [0, 1].map(|actor| ProductionRosterMemberV1 {
            participant_id: participants[actor],
            xonly_key: secp.xonly_public_key(&relay[actor][l]).unwrap(),
            role: if actor == 0 {
                SenderRoleV1::Initiator
            } else {
                SenderRoleV1::Solver
            },
        });
        members.sort_by_key(|m| m.participant_id);
        legs.push(ProductionRosterLegV1 {
            position: if l == 0 {
                ProductionRoutePositionV1::Upstream
            } else {
                ProductionRoutePositionV1::Downstream
            },
            session_id: terms[l].session_id.0,
            roster_snapshot: [71 + l as u8; 32],
            policy_version: terms[l].policy_version,
            members,
        });
    }
    let rosters =
        ProductionRelayRosterBundleV1::new(manifest.network_id, [70; 32], legs.try_into().unwrap())
            .unwrap();
    let roster_path = root.path().join("rosters.bin");
    write(&roster_path, &rosters.canonical_bytes().unwrap());
    let budget_path = root.path().join("budget.bin");
    write(&budget_path, policy().as_bytes());
    let plans = [
        root.path().join("alice-plan.json"),
        root.path().join("bob-plan.json"),
    ];
    for actor in 0..2 {
        let plan = Plan {
            schema: 13,
            network_id: manifest.network_id,
            route_id: [70; 32],
            registry_authority_set_digest: authorities.authority_set_digest().unwrap(),
            registry_manifest_digest: digest,
            minimum_registry_epoch: manifest.epoch,
            terms_digests: [
                terms[0].terms_hash().unwrap(),
                terms[1].terms_hash().unwrap(),
            ],
            roster_digest: rosters.bundle_digest().unwrap(),
            local_participant_id: participants[actor].0,
            authority_bundle_file: authority_path.clone(),
            registry_store: registry_path.clone(),
            terms_files: terms_paths.clone(),
            xmr_compensation_policy_files: xmr_policy_files.clone(),
            roster_file: roster_path.clone(),
            identity_store: identities[actor].clone(),
            budget_policy_file: budget_path.clone(),
        };
        write(&plans[actor], &serde_json::to_vec(&plan).unwrap());
    }
    let credentials=[0,1].map(|actor|serde_json::to_vec(&serde_json::json!({"identity_passphrase":"test-passphrase-v13",
        "upstream_relay_secret":hex::encode(relay[actor][0]),"downstream_relay_secret":hex::encode(relay[actor][1])})).unwrap());
    Fixture {
        _root: root,
        work,
        plan: plans,
        credentials,
    }
}

fn completed_fixture_v16() -> (Fixture, Vec<u8>) {
    completed_fixture_with_xmr(false)
}

fn completed_fixture_with_xmr(xmr: bool) -> (Fixture, Vec<u8>) {
    complete_fixture(fixture_with_xmr(xmr))
}

fn complete_fixture(f: Fixture) -> (Fixture, Vec<u8>) {
    let mut completed = [false; 2];
    let mut final_packets: Option<Vec<u8>> = None;
    for _round in 0..8 {
        for actor in 0..2 {
            let report = execute(&f.plan[actor], &f.work[actor], &f.credentials[actor]).unwrap();
            assert!(!report.funding_authorized);
            if matches!(report.stage, "offers" | "commit-signature") {
                assert!(!report
                    .local_packets
                    .iter()
                    .any(|n| n.starts_with("reveal-")));
            }
            if report.stage == "complete" {
                completed[actor] = true;
            }
            for name in report.local_packets {
                let bytes = std::fs::read(f.work[actor].join(&name)).unwrap();
                if name == ARTIFACT {
                    if let Some(old) = &final_packets {
                        assert_eq!(old, &bytes);
                    } else {
                        final_packets = Some(bytes);
                    }
                } else {
                    let other = f.work[actor ^ 1].join(name);
                    if other.exists() {
                        assert_eq!(std::fs::read(other).unwrap(), bytes);
                    } else {
                        write(&other, &bytes);
                    }
                }
            }
        }
        if completed == [true; 2] {
            break;
        }
    }
    assert_eq!(completed, [true; 2]);
    (f, final_packets.unwrap())
}

#[test]
fn native_two_participant_ceremony_reopens_each_barrier_and_mounts_exact_private_shares() {
    let (f, bytes) = completed_fixture_v16();
    let final_packets = Some(bytes);
    for actor in 0..2 {
        let plan: Plan = serde_json::from_slice(&std::fs::read(&f.plan[actor]).unwrap()).unwrap();
        let secp = SecpContext::new(&[13; 32]);
        let context = load_context(&plan, &secp, true).unwrap();
        let verified = authenticate_against_expected_v1(
            final_packets.as_ref().unwrap(),
            &context.expected,
            &context.rosters,
            &secp,
        )
        .unwrap();
        let positions = [0, 1].map(|l| {
            context.rosters.legs()[l]
                .members
                .iter()
                .position(|m| m.participant_id.0 == plan.local_participant_id)
                .unwrap()
        });
        let bindings = [
            context.bindings[0][positions[0]],
            context.bindings[1][positions[1]],
        ];
        let mount = || {
            resume_completed_bootstrap_v13(
                &f.work[actor].join(ARTIFACT),
                &verified,
                bindings,
                &plan.identity_store,
                b"test-passphrase-v13",
            )
        };
        let owners = mount().unwrap().unwrap();
        for l in 0..2 {
            assert_eq!(
                owners._shares[l]
                    .capability
                    .binding()
                    .share_point()
                    .to_compressed_bytes(),
                *verified.legs()[l].participants()[positions[l]].share_point()
            );
        }
        // The live owner excludes concurrent reopen, then admits exact restart.
        assert!(mount().is_err());
        drop(owners);
        drop(mount().unwrap().unwrap());
        assert!(resume_completed_bootstrap_v13(
            &f.work[actor].join(ARTIFACT),
            &verified,
            bindings,
            &plan.identity_store,
            b"wrong passphrase"
        )
        .is_err());
        let vault = std::fs::read_dir(&f.work[actor])
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("dom-vault-v12-")
            })
            .unwrap();
        let saved_vault = vault.with_extension("retained");
        std::fs::rename(&vault, &saved_vault).unwrap();
        assert!(mount().is_err());
        assert!(!vault.exists());
        std::fs::rename(saved_vault, vault).unwrap();
        let private = f.work[actor].join(format!("shared-{}.sqlite", positions[0]));
        let saved = private.with_extension("retained");
        std::fs::rename(&private, &saved).unwrap();
        assert!(mount().is_err());
        assert!(!private.exists());
        std::fs::rename(saved, private).unwrap();
        let mut altered = final_packets.as_ref().unwrap().clone();
        altered[1200] ^= 1;
        write(&f.work[actor].join(ARTIFACT), &altered);
        assert!(mount().is_err());
        write(
            &f.work[actor].join(ARTIFACT),
            final_packets.as_ref().unwrap(),
        );
        drop(mount().unwrap().unwrap());
        let plan_path = f.work[actor].join(PLAN);
        let original = std::fs::read(&plan_path).unwrap();
        std::fs::remove_file(&plan_path).unwrap();
        assert!(mount().is_err());
        write(&plan_path, &original);
    }
}

#[test]
fn wrong_relay_key_refuses_before_share_creation() {
    let f = fixture();
    let mut secrets: serde_json::Value = serde_json::from_slice(&f.credentials[0]).unwrap();
    secrets["upstream_relay_secret"] = serde_json::Value::String(hex::encode([99; 32]));
    assert!(execute(
        &f.plan[0],
        &f.work[0],
        &serde_json::to_vec(&secrets).unwrap()
    )
    .is_err());
    assert!(!std::fs::read_dir(&f.work[0]).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("dom-vault-")));
}

#[test]
fn interrupted_empty_vault_preparation_is_quarantined_before_any_offer_or_share() {
    let f = fixture();
    let plan: Plan = serde_json::from_slice(&std::fs::read(&f.plan[0]).unwrap()).unwrap();
    let secp = SecpContext::new(&[13; 32]);
    let context = load_context(&plan, &secp, false).unwrap();
    let p = context.rosters.legs()[0]
        .members
        .iter()
        .position(|m| m.participant_id.0 == plan.local_participant_id)
        .unwrap();
    let b = context.bindings[0][p];
    let mut name_context = Vec::new();
    for value in [
        b.route_id(),
        b.session_id(),
        b.chain_id(),
        b.terms_digest(),
        b.participant().participant_id(),
    ] {
        name_context.extend_from_slice(&value);
    }
    name_context.push(1); // registered SharedOutput purpose
    let name = hex::encode(hash(b"DOM-INTEROPD/DOM-VAULT-NAME/V12\0", &name_context).unwrap());
    let stage = f.work[0].join(format!("bootstrap-staging-v13-dom-vault-v12-{name}"));
    directory(&stage);
    write(
        &stage.join("interrupted-private-creation"),
        b"preserve this incomplete inventory",
    );
    let result = execute(&f.plan[0], &f.work[0], &f.credentials[0]).unwrap();
    assert_eq!(result.stage, "offers");
    let quarantine = std::fs::read_dir(&f.work[0])
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("bootstrap-quarantine-v13-")
        })
        .unwrap();
    assert_eq!(
        std::fs::read(quarantine.join("interrupted-private-creation")).unwrap(),
        b"preserve this incomplete inventory"
    );
    assert!(f.work[0].join(format!("dom-vault-v12-{name}")).is_dir());
    assert!(!result
        .local_packets
        .iter()
        .any(|n| n.starts_with("reveal-")));
}

#[test]
fn v16_two_native_owners_complete_bp_with_restart_after_every_tick() {
    two_native_owners_complete_bp_with_restart_after_every_tick(BootstrapProofCase::Ordinary);
}

#[test]
fn v22_two_native_d_owners_complete_bp_with_restart_after_every_tick() {
    two_native_owners_complete_bp_with_restart_after_every_tick(BootstrapProofCase::Cancelled);
}

#[test]
fn v22_xmr_collateral_proof_restarts_without_authorizing_funding_before_recovery_graph() {
    two_native_owners_complete_bp_with_restart_after_every_tick(BootstrapProofCase::Collateral);
}

enum BootstrapProofCase {
    Ordinary,
    Cancelled,
    Collateral,
}

fn two_native_owners_complete_bp_with_restart_after_every_tick(case: BootstrapProofCase) {
    let (fixture, artifact) =
        completed_fixture_with_xmr(!matches!(case, BootstrapProofCase::Ordinary));
    let _ = complete_native_proof_in_fixture(case, &fixture, &artifact);
}

fn native_runtime_worker_paths(work: &Path, prefix: &str) -> [PathBuf; 3] {
    ["sender", "inbox", "frames"].map(|role| work.join(format!("{prefix}-{role}")))
}

#[test]
fn v23_native_runtime_worker_paths_separate_c_and_d() {
    let root = Path::new("test-runtime-root");
    let c = native_runtime_worker_paths(root, "runtime");
    let d = native_runtime_worker_paths(root, "runtime-d");
    for path in &c {
        assert!(!d.contains(path));
    }
    let all: std::collections::BTreeSet<_> = c.iter().chain(&d).collect();
    assert_eq!(all.len(), 6);
    assert_eq!(c, native_runtime_worker_paths(root, "runtime"));
    assert_eq!(d, native_runtime_worker_paths(root, "runtime-d"));
}

type NativeGraphOutput = (
    dom_scriptless_crypto::FrozenSharedOutputV1,
    dom_adaptor::VerifiedSharedOutputV1,
);

fn complete_native_proof_in_fixture(
    case: BootstrapProofCase,
    fixture: &Fixture,
    artifact: &[u8],
) -> [Option<NativeGraphOutput>; 2] {
    complete_native_proof_in_fixture_for_leg(case, fixture, artifact, 0)
}

fn complete_native_proof_in_fixture_for_leg(
    case: BootstrapProofCase,
    fixture: &Fixture,
    artifact: &[u8],
    leg_index: usize,
) -> [Option<NativeGraphOutput>; 2] {
    let mut timing = native_proof_timing_v25::NativeProofTimingV25::new();
    assert!(leg_index < 2);
    let cancelled = matches!(case, BootstrapProofCase::Cancelled);
    let collateral = matches!(case, BootstrapProofCase::Collateral);
    use crate::production_config::ProductionRelayAuthorityPinsV6;
    use crate::production_contracts::{ProductionBootstrapLegV16, ProductionContractsV1};
    use crate::relay_worker::{RelayWorkerConfigV1, RelayWorkerPathsV1, UnavailableF6AuthorityV1};
    use dom_adaptor::{initial_transcript_hash_v1, ParticipantIdentityV1, ParticipantRosterV1};
    use dom_crypto::PublicKey;
    use dom_scriptless_store::{
        ContractsSessionStoreV1, SessionChainProjectionV1, SessionIrreversibleV1, SessionPhaseV1,
        SessionRecordFieldsV1, SessionRecordV1, SessionTransportIdentityReferenceV1,
        SessionTransportParticipantV1, SessionTxObservationV1,
    };
    use relay::auth::{RosterMemberV1, RosterRegistryV1, RosterSnapshotV1};
    use relay::production::{ProductionRelayV1, RelayDatabaseConfigV1, RelayDatabaseIdV1};
    use relay::TimelockSpec;
    use route_executor::LegIdV1;
    use route_transport::{
        DurableFrameReassemblerConfigV2, DurableInboxConfigV1, DurableRelaySenderConfigV1,
        RouteWireContextV1,
    };
    let prefix = match (leg_index, cancelled) {
        (0, false) => "runtime",
        (0, true) => "runtime-d",
        (_, false) => "runtime-leg1",
        (_, true) => "runtime-d-leg1",
    };
    let parent_contracts = if leg_index == 0 {
        "runtime-contracts"
    } else {
        "runtime-contracts-leg1"
    };
    let mut outputs = [None, None];
    let plans: [Plan; 2] = [0, 1].map(|actor| {
        serde_json::from_slice(&std::fs::read(&fixture.plan[actor]).unwrap()).unwrap()
    });
    let secp = SecpContext::new(&[16; 32]);
    let context = load_context(&plans[0], &secp, true).unwrap();
    let verified =
        authenticate_against_expected_v1(&artifact, &context.expected, &context.rosters, &secp)
            .unwrap();
    let leg = &verified.legs()[leg_index];
    let mut queue = ProductionRelayV1::create(
        &fixture._root.path().join(format!("{prefix}-relay")),
        RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0xd1; 32]).unwrap(), 256).unwrap(),
    )
    .unwrap();
    let mut completed = [false; 2];
    let mut last_heads = [None, None];
    let mut revisions = [0; 2];
    for _ in 0..80 {
        for actor in 0..2 {
            timing.begin_actor_tick();
            let plan = &plans[actor];
            let positions = [0, 1].map(|l| {
                context.rosters.legs()[l]
                    .members
                    .iter()
                    .position(|m| m.participant_id.0 == plan.local_participant_id)
                    .unwrap()
            });
            let bindings = [
                context.bindings[0][positions[0]],
                context.bindings[1][positions[1]],
            ];
            timing.begin_tick_mount();
            let mut mounted = resume_completed_bootstrap_v13(
                &fixture.work[actor].join(ARTIFACT),
                &verified,
                bindings,
                &plan.identity_store,
                b"test-passphrase-v13",
            )
            .unwrap()
            .unwrap();
            timing.resume_tick();
            let material = if cancelled {
                mounted._cancelled_shares[leg_index].as_mut().unwrap()
            } else {
                &mut mounted._shares[leg_index]
            };
            let bp_binding = if cancelled {
                bindings[leg_index].for_xmr_cancelled_output_v22().unwrap()
            } else {
                bindings[leg_index]
            };
            let bp_session = bp_binding.session_id();
            timing.begin_identity_open();
            let identity = ContractsTransportIdentityStoreV1::open_production(
                private_directory(plan.identity_store.parent().unwrap()).unwrap(),
                "identity",
                &ContractsIdentityPassphraseV1::new(b"test-passphrase-v13".to_vec()).unwrap(),
            )
            .unwrap();
            timing.resume_tick();
            let parent = private_directory(&fixture.work[actor]).unwrap();
            let contracts_name = if cancelled {
                format!(
                    "cancelled-contracts-{}",
                    2 * leg_index + positions[leg_index]
                )
            } else {
                parent_contracts.to_owned()
            };
            let store_exists = fixture.work[actor].join(&contracts_name).exists();
            let worker_paths = native_runtime_worker_paths(&fixture.work[actor], prefix);
            let exists = worker_paths[0].exists();
            if cancelled {
                assert!(
                    store_exists,
                    "the real bootstrap must provision D Contracts"
                );
            }
            let store = if cancelled {
                mounted._cancelled_contracts[leg_index]
                    .take()
                    .unwrap()
                    .store
            } else if store_exists {
                ContractsSessionStoreV1::open_production(parent, &contracts_name, policy()).unwrap()
            } else {
                ContractsSessionStoreV1::create_production(parent, &contracts_name, policy())
                    .unwrap()
            };
            if cancelled {
                use crate::production_contracts_session_bootstrap::xmr_cancelled_v22::{
                    initialize, CancelledContractsRequestV22,
                };
                let request = || CancelledContractsRequestV22 {
                    parent: bindings[leg_index],
                    parent_leg: leg,
                    chain: context.chain,
                    roster: context.rosters.legs()[leg_index],
                    policy: context.xmr_policies[leg_index].as_ref().unwrap(),
                    material: &*material,
                    identity: &identity,
                };
                if !exists {
                    let empty = ContractsSessionStoreV1::create_production(
                        private_directory(&fixture.work[actor]).unwrap(),
                        if leg_index == 0 {
                            "cancelled-negative-empty"
                        } else {
                            "cancelled-negative-empty-leg1"
                        },
                        policy(),
                    )
                    .unwrap();
                    assert!(initialize(&empty, request(), false).is_err());
                    let mut foreign = request();
                    foreign.parent = bindings[leg_index ^ 1];
                    assert!(initialize(&empty, foreign, true).is_err());
                    assert!(matches!(
                        empty.load_session(bp_session),
                        Err(dom_scriptless_store::SessionStoreError::SessionNotFound)
                    ));
                }
                // Reopen the origin provisioned by the actual bootstrap command.
                // The tick reissues ingress for the authenticated current phase.
                let _early = initialize(&store, request(), false).unwrap();
            } else if !exists {
                let participants: Vec<_> = leg
                    .participants()
                    .iter()
                    .enumerate()
                    .map(|(index, p)| {
                        ParticipantIdentityV1::new(
                            &context.chain,
                            PublicKey::from_compressed_bytes(p.schnorr_public_key()).unwrap(),
                            material.shared_bindings_v22()[index].share_point().clone(),
                            p.direction(),
                        )
                        .unwrap()
                    })
                    .collect();
                let roster = ParticipantRosterV1::new(participants).unwrap();
                store
                    .create_session(
                        &SessionRecordV1::new(
                            SessionRecordFieldsV1 {
                                session_id: bp_session,
                                revision: 0,
                                phase: SessionPhaseV1::Created,
                                terms_hash: *leg.terms_hash(),
                                transcript_hash: initial_transcript_hash_v1(
                                    &context.chain,
                                    &bp_session,
                                    verified.contract_kind(),
                                    &roster,
                                ),
                                irreversible: SessionIrreversibleV1 {
                                    any_signing_share_sent: false,
                                    funding_authorized: false,
                                    adaptor_secret_exposed: false,
                                    nonce_epoch: 0,
                                },
                                chain: SessionChainProjectionV1 {
                                    tip_id: bindings[leg_index].genesis_hash(),
                                    tip_height: 0,
                                    funding: SessionTxObservationV1::Unknown,
                                    claim: SessionTxObservationV1::Unknown,
                                    refund: SessionTxObservationV1::Unknown,
                                },
                            },
                            &[],
                        )
                        .unwrap(),
                    )
                    .unwrap();
                let ordered = [
                    dom_adaptor::DirectionV1::Initiator,
                    dom_adaptor::DirectionV1::Responder,
                ]
                .map(|direction| {
                    leg.participants()
                        .iter()
                        .find(|p| p.direction() == direction)
                        .unwrap()
                });
                store
                    .bind_transport_roster(
                        bp_session,
                        *context.chain.as_bytes(),
                        ordered.map(|p| {
                            SessionTransportParticipantV1::new(
                                p.participant_id().0,
                                PublicKey::from_compressed_bytes(p.schnorr_public_key()).unwrap(),
                                p.direction(),
                            )
                            .unwrap()
                        }),
                    )
                    .unwrap();
                store
                    .bind_transport_identity_references(
                        bp_session,
                        ordered.map(|p| {
                            SessionTransportIdentityReferenceV1::new(
                                p.participant_id().0,
                                *p.key_reference(),
                                *p.noise_public_key(),
                                PublicKey::from_compressed_bytes(p.schnorr_public_key()).unwrap(),
                            )
                            .unwrap()
                        }),
                    )
                    .unwrap();
            }
            let roster_leg = &context.rosters.legs()[leg_index];
            let local = &roster_leg.members[positions[leg_index]];
            let remote = &roster_leg.members[positions[leg_index] ^ 1];
            let wire = RouteWireContextV1 {
                network_id: plan.network_id,
                session_id: bp_session,
                route_id: plan.route_id,
                roster_snapshot: roster_leg.roster_snapshot,
                policy_version: roster_leg.policy_version,
            };
            let pins = ProductionRelayAuthorityPinsV6 {
                relay_database_id: [0xd1; 32],
                upstream_sender_store_id: [0x14; 32],
                upstream_inbox_id: [0x15; 32],
                upstream_reassembler_id: [0x16; 32],
                downstream_sender_store_id: [0x17; 32],
                downstream_inbox_id: [0x18; 32],
                downstream_reassembler_id: [0x19; 32],
                relay_max_envelopes: 256,
                sender_max_envelopes: 128,
                inbox_max_entries: 128,
                frame_max_messages: 16,
                frame_max_active_bytes: 2 * 1024 * 1024,
                frame_max_active_chunks: 128,
            };
            let config = RelayWorkerConfigV1::new_production_v6(
                DurableRelaySenderConfigV1::new(
                    if leg_index == 0 {
                        [0x14; 32]
                    } else {
                        [0x17; 32]
                    },
                    wire,
                    local.participant_id,
                    remote.participant_id,
                    local.role,
                    local.xonly_key,
                    128,
                )
                .unwrap(),
                DurableInboxConfigV1::new(
                    if leg_index == 0 {
                        [0x15; 32]
                    } else {
                        [0x18; 32]
                    },
                    [0xd1; 32],
                    wire,
                    local.participant_id,
                    128,
                )
                .unwrap(),
                DurableFrameReassemblerConfigV2::new(
                    if leg_index == 0 {
                        [0x16; 32]
                    } else {
                        [0x19; 32]
                    },
                    wire,
                    local.participant_id,
                    16,
                    2 * 1024 * 1024,
                    128,
                )
                .unwrap(),
                pins,
                if leg_index == 0 {
                    LegIdV1::Upstream
                } else {
                    LegIdV1::Downstream
                },
            )
            .unwrap();
            let registry = RosterRegistryV1::new().with_snapshot(
                wire.roster_snapshot,
                RosterSnapshotV1::new()
                    .with_member(
                        local.participant_id,
                        RosterMemberV1 {
                            xonly_key: local.xonly_key,
                            role: local.role,
                        },
                    )
                    .with_member(
                        remote.participant_id,
                        RosterMemberV1 {
                            xonly_key: remote.xonly_key,
                            role: remote.role,
                        },
                    ),
            );
            let [sender_path, inbox_path, frames_path] = worker_paths;
            let paths = RelayWorkerPathsV1::new(sender_path, inbox_path, frames_path);
            let mut owner = if exists {
                ProductionContractsV1::open_existing(
                    store,
                    identity,
                    &paths,
                    config,
                    registry,
                    UnavailableF6AuthorityV1,
                    if actor == 0 {
                        [21 + leg_index as u8; 32]
                    } else {
                        [23 + leg_index as u8; 32]
                    },
                )
            } else {
                ProductionContractsV1::create(
                    store,
                    identity,
                    &paths,
                    config,
                    registry,
                    UnavailableF6AuthorityV1,
                    if actor == 0 {
                        [21 + leg_index as u8; 32]
                    } else {
                        [23 + leg_index as u8; 32]
                    },
                )
            }
            .unwrap();
            let mut driver = if cancelled {
                ProductionBootstrapLegV16::for_xmr_cancelled_v22(
                    bindings[leg_index],
                    context.chain,
                    context.rosters.legs()[leg_index],
                    context.xmr_policies[leg_index].as_ref().unwrap(),
                    material,
                )
            } else if collateral {
                let terms = SettlementTermsV1::decode(
                    &std::fs::read(&plan.terms_files[leg_index]).unwrap(),
                )
                .unwrap();
                ProductionBootstrapLegV16::for_xmr_collateral_v22(
                    bindings[leg_index],
                    context.chain,
                    leg,
                    &terms,
                    context.xmr_policies[leg_index].as_ref().unwrap(),
                    material,
                )
            } else {
                ProductionBootstrapLegV16::new(
                    bindings[leg_index],
                    context.chain,
                    leg,
                    100,
                    material,
                )
            }
            .unwrap();
            let step = driver.step(&mut owner, material, 100);
            let graph_required = matches!(
                &step,
                Err(crate::production_contracts::ProductionBootstrapRuntimeErrorV16::XmrRecoveryGraphRequired)
            );
            if !collateral || !graph_required {
                step.unwrap();
            }
            if graph_required || (cancelled && driver.complete()) {
                let frozen = driver.frozen_xmr_formation_v22().expect(
                    "completed native C/D proof must retain journal-authenticated formation",
                );
                let policy = context.xmr_policies[leg_index].as_ref().unwrap();
                assert_eq!(
                    frozen.value_noms(),
                    if cancelled {
                        policy.cancelled_noms()
                    } else {
                        policy.collateral_noms()
                    }
                );
                assert_eq!(frozen.statement().session_id(), bp_session);
                assert_eq!(frozen.terms_hash(), policy.terms_hash());
                let verified = driver
                    .verified_xmr_output_v22()
                    .expect("completed C/D formation must carry the exact verified journal output");
                assert_eq!(
                    verified.commitment(),
                    &frozen
                        .statement()
                        .aggregate_commitment()
                        .to_compressed_bytes()
                );
                assert_eq!(
                    verified
                        .output()
                        .recovery_capsule()
                        .unwrap()
                        .unwrap()
                        .as_bytes(),
                    material.capsule.as_bytes()
                );
                let (owned_formation, owned_output) = driver
                    .xmr_graph_output_v22(&owner, material)
                    .unwrap()
                    .expect("graph input must reopen the native formation without consuming it");
                assert_eq!(
                    owned_formation.aggregate_commitment(),
                    frozen.aggregate_commitment()
                );
                assert_eq!(owned_formation.terms_hash(), frozen.terms_hash());
                assert_eq!(owned_output.output(), verified.output());
                outputs[actor] = Some((owned_formation, owned_output));
            }
            if collateral {
                assert!(
                    !driver.complete(),
                    "C proof cannot bypass recovery graph custody"
                );
            }
            owner.submit_outbound_once(&mut queue).unwrap();
            owner
                .poll_inbound(&mut queue, TimelockSpec::TimestampSeconds { value: 100 })
                .unwrap();
            let status = owner.contracts_session_status().unwrap();
            assert!(status.revision >= revisions[actor]);
            revisions[actor] = status.revision;
            last_heads[actor] = Some(status.phase);
            completed[actor] = if collateral {
                graph_required
            } else {
                driver.complete()
            };
            // Both private custody and every native Contracts/Relay owner are
            // dropped here. The next tick has no in-memory signing state.
        }
        if completed == [true; 2] {
            break;
        }
    }
    timing.begin_terminal_audit();
    assert_eq!(completed, [true; 2]);
    assert_eq!(last_heads, [Some(SessionPhaseV1::OutputFinalized); 2]);
    assert_eq!(revisions, [17; 2]);
    // Reopen independently of the driver's in-memory completion flag, verify
    // the native proof transcript at the policy amount, and compare both peers.
    let mut proof_digests = Vec::new();
    for actor in 0..2 {
        let plan = &plans[actor];
        let bindings = [0, 1].map(|index| {
            let position = context.rosters.legs()[index]
                .members
                .iter()
                .position(|m| m.participant_id.0 == plan.local_participant_id)
                .unwrap();
            context.bindings[index][position]
        });
        timing.begin_terminal_mount();
        let mut mounted = resume_completed_bootstrap_v13(
            &fixture.work[actor].join(ARTIFACT),
            &verified,
            bindings,
            &plan.identity_store,
            b"test-passphrase-v13",
        )
        .unwrap()
        .unwrap();
        timing.resume_terminal_audit();
        let material = if cancelled {
            mounted._cancelled_shares[leg_index].as_ref().unwrap()
        } else {
            &mounted._shares[leg_index]
        };
        let binding = if cancelled {
            bindings[leg_index].for_xmr_cancelled_output_v22().unwrap()
        } else {
            bindings[leg_index]
        };
        let store = if cancelled {
            mounted._cancelled_contracts[leg_index]
                .take()
                .unwrap()
                .store
        } else {
            ContractsSessionStoreV1::open_production(
                private_directory(&fixture.work[actor]).unwrap(),
                parent_contracts,
                policy(),
            )
            .unwrap()
        };
        let amount = if cancelled {
            context.xmr_policies[leg_index]
                .as_ref()
                .unwrap()
                .cancelled_noms()
        } else if collateral {
            context.xmr_policies[leg_index]
                .as_ref()
                .unwrap()
                .collateral_noms()
        } else {
            100
        };
        let statement = |value| {
            let points = material
                .shared_bindings_v22()
                .iter()
                .map(|public| public.share_point().clone())
                .collect::<Vec<_>>();
            let commitment =
                dom_adaptor::BpStatementV1::aggregate_commitment_from_shares(&points, value)
                    .unwrap();
            dom_adaptor::BpStatementV1::new(
                &context.chain,
                binding.session_id(),
                material.capability.binding().roster().to_vec(),
                value,
                points,
                commitment,
                Some(*dom_crypto::blake2b_256(material.capsule.as_bytes()).as_bytes()),
            )
            .unwrap()
        };
        let proof = store
            .completed_operational_bp_proof_v16(
                context.chain,
                binding.session_id(),
                binding.terms_digest(),
                &statement(amount),
                &material.capsule,
            )
            .unwrap()
            .unwrap();
        proof_digests.push(proof.proof_digest());
        if collateral {
            let terms =
                SettlementTermsV1::decode(&std::fs::read(&plan.terms_files[leg_index]).unwrap())
                    .unwrap();
            let ordinary_budget = dom_adaptor::DomBootstrapBudgetV17::new(
                terms.dom_leg.amount,
                terms.fee_limit.dom_max,
            );
            if terms.fee_limit.dom_max == 10 {
                // Preserve the original tiny-fee fixture's explicit refusal.
                assert!(ordinary_budget.is_err());
            } else {
                // Wallet-backed fixtures have room for native funding fees,
                // but their XMR collateral is still not an ordinary V17 output.
                assert_ne!(ordinary_budget.unwrap().shared_value(), amount);
            }
            let ordinary_value = u64::try_from(terms.dom_leg.amount).unwrap();
            assert_ne!(ordinary_value, amount);
            assert!(
                store
                    .completed_operational_bp_proof_v16(
                        context.chain,
                        binding.session_id(),
                        binding.terms_digest(),
                        &statement(ordinary_value),
                        &material.capsule,
                    )
                    .is_err(),
                "the bare trade principal is not an XMR collateral proof"
            );
        }
        assert!(store
            .completed_operational_bp_proof_v16(
                context.chain,
                binding.session_id(),
                binding.terms_digest(),
                &statement(amount + 1),
                &material.capsule,
            )
            .is_err());
        assert!(store
            .completed_operational_bp_proof_v16(
                context.chain,
                binding.session_id(),
                binding.terms_digest(),
                &statement(amount),
                &material.capsule,
            )
            .unwrap()
            .is_some());
    }
    assert_eq!(proof_digests[0], proof_digests[1]);
    eprintln!(
        "{}",
        timing.finish().public_summary(
            leg_index,
            if cancelled {
                "cancelled"
            } else if collateral {
                "collateral"
            } else {
                "ordinary"
            },
        )
    );
    outputs
}
