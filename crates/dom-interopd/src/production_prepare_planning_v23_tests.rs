use super::*;
use crate::production_inputs::{
    ProductionRosterLegV1, ProductionRosterMemberV1, ProductionRoutePositionV1,
};
use crate::route_time_test_common as common;
use deployment_registry::{AuthoritySetV1, RegistrySignatureV1};
use relay::SenderRoleV1;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

fn artifact(bytes: Vec<u8>) -> ArtifactSource {
    ArtifactSource::CanonicalHex {
        hex: hex::encode(bytes),
    }
}

fn fixture() -> PublicInput {
    let fixture = common::fixture();
    let registry_secrets = [[3; 32], [4; 32], [5; 32]];
    let registry_authorities = AuthoritySetV1::new(
        2,
        registry_secrets
            .iter()
            .map(|secret| {
                fixture
                    .secp
                    .sign_bip340(secret, &[7; 32], &[8; 32])
                    .unwrap()
                    .1
            })
            .collect(),
    )
    .unwrap();
    let signed_registry = SignedRegistryV1::new(
        fixture.registry.manifest(),
        common::sign_digest(
            &fixture.secp,
            &registry_secrets,
            &fixture.registry.manifest_digest(),
            0x50,
        )
        .into_iter()
        .map(|signature| RegistrySignatureV1 {
            signer_index: signature.signer_index,
            signature: signature.signature,
        })
        .collect(),
    )
    .unwrap();
    let authorities = ProductionAuthorityBundleV1::new(
        registry_authorities,
        fixture.policy_authorities.clone(),
        fixture.evidence_authorities.clone(),
    )
    .unwrap();
    let roster = ProductionRelayRosterBundleV1::new(
        common::REGISTRY_NETWORK,
        [0xa7; 32],
        std::array::from_fn(|index| {
            let terms = [&fixture.upstream, &fixture.downstream][index];
            ProductionRosterLegV1 {
                position: if index == 0 {
                    ProductionRoutePositionV1::Upstream
                } else {
                    ProductionRoutePositionV1::Downstream
                },
                session_id: terms.session_id.0,
                roster_snapshot: [0xa8 + index as u8; 32],
                policy_version: terms.policy_version,
                members: std::array::from_fn(|member| ProductionRosterMemberV1 {
                    participant_id: terms.roster[member],
                    xonly_key: fixture
                        .secp
                        .sign_bip340(&[0x61 + member as u8; 32], &[7; 32], &[8; 32])
                        .unwrap()
                        .1,
                    role: if member == 0 {
                        SenderRoleV1::Initiator
                    } else {
                        SenderRoleV1::Solver
                    },
                }),
            }
        }),
    )
    .unwrap();
    PublicInput {
        schema: SCHEMA.into(),
        network_id: common::REGISTRY_NETWORK,
        route_id: [0xa7; 32],
        minimum_registry_epoch: fixture.registry.epoch(),
        authorities: artifact(authorities.canonical_bytes().unwrap()),
        signed_registry: artifact(signed_registry.canonical_bytes().unwrap()),
        upstream_terms: artifact(fixture.upstream.canonical_bytes().unwrap()),
        downstream_terms: artifact(fixture.downstream.canonical_bytes().unwrap()),
        relay_roster: artifact(roster.canonical_bytes().unwrap()),
        signed_time_policy: artifact(common::signed_policy(&fixture).canonical_bytes().unwrap()),
        signed_time_evidence: artifact(
            common::signed_evidence(
                &fixture,
                &common::evidence(&fixture.policy, 1, common::EVIDENCE_TIME, 0),
            )
            .canonical_bytes()
            .unwrap(),
        ),
    }
}

fn directory() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn write_input(root: &Path, input: &PublicInput) -> PathBuf {
    let path = root.join("input.json");
    fs::write(&path, serde_json::to_vec(input).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn corrupt_last_byte(source: &mut ArtifactSource) {
    let ArtifactSource::CanonicalHex { hex } = source else {
        panic!("inline fixture");
    };
    let mut bytes = hex::decode(&*hex).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    *hex = hex::encode(bytes);
}

#[test]
fn production_planning_exports_real_pins_stable_across_startup_delays() {
    let root = directory();
    let input_file = write_input(root.path(), &fixture());
    let first = root.path().join("first");
    let second = root.path().join("second");
    let first_report =
        prepare_with_clock(&input_file, &first, || Ok(common::EVIDENCE_TIME + 1)).unwrap();
    let second_report =
        prepare_with_clock(&input_file, &second, || Ok(common::EVIDENCE_TIME + 2)).unwrap();
    assert_eq!(first_report.route, second_report.route);
    assert_eq!(
        first_report.original_validation_seconds,
        common::EVIDENCE_TIME
    );
    assert_eq!(first_report.validated_at_seconds, common::EVIDENCE_TIME + 1);
    assert!(!first_report.grants_funding_authority);
    assert!(!first_report.network_access);
    assert_eq!(first_report.route.as_object().unwrap().len(), 7);
    assert_ne!(
        first_report.route["composition_digest"],
        serde_json::json!(vec![0u8; 32])
    );
    assert_ne!(
        first_report.route["profile_bundle_digest"],
        serde_json::json!(vec![0u8; 32])
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(first.join(ROUTE)).unwrap()).unwrap(),
        first_report.route
    );
    assert_eq!(
        serde_json::from_slice::<PreparedPlanningReportV23>(&fs::read(first.join(REPORT)).unwrap())
            .unwrap(),
        first_report
    );
    assert_eq!(fs::metadata(&first).unwrap().mode() & 0o7777, 0o700);
    for entry in fs::read_dir(&first).unwrap() {
        let metadata = entry.unwrap().metadata().unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }
    assert!(!root.path().join("first.preparing-v23").exists());
    // A genuine authenticated admission, not caller-chosen profile pins.
    let mut public = fixture();
    let decoded = DecodedInput::from_input(&mut public).unwrap();
    let input = decoded.planning(common::EVIDENCE_TIME + 3);
    let secp = SecpContext::new(&[9; 32]);
    let registry = RegistryStoreV1::create(&root.path().join("reference.sqlite")).unwrap();
    let mut time = DurableRouteTimeAnchorStoreV2::create(
        &root.path().join("reference-time.sqlite"),
        input.time_store_config(&secp).unwrap(),
    )
    .unwrap();
    let context =
        ProductionPreF6PlanningContextV23::prepare(registry, &mut time, &input, &secp).unwrap();
    let (admission, composition, _) = context.into_parts();
    assert_eq!(
        first_report.route["composition_digest"],
        serde_json::json!(composition.binding_digest())
    );
    assert_eq!(
        first_report.route["profile_bundle_digest"],
        serde_json::json!(admission.frozen_bindings().profile_bundle_digest)
    );
}

#[test]
fn planning_rejects_invalid_signed_registry_and_scope_before_staging() {
    for mutation in 0..4 {
        let root = directory();
        let mut input = fixture();
        match mutation {
            0 => corrupt_last_byte(&mut input.signed_registry),
            1 => input.minimum_registry_epoch += 1,
            2 => input.route_id = [99; 32],
            _ => input.network_id = [99; 32],
        }
        let path = write_input(root.path(), &input);
        assert!(prepare_with_clock(&path, &root.path().join("plan"), || Ok(
            common::EVIDENCE_TIME
        ))
        .is_err());
        assert!(!root.path().join("plan").exists());
        assert!(!root.path().join("plan.preparing-v23").exists());
    }
}

#[test]
fn planning_rejects_invalid_time_signatures_and_preserves_partial_state() {
    for policy in [true, false] {
        let root = directory();
        let mut input = fixture();
        corrupt_last_byte(if policy {
            &mut input.signed_time_policy
        } else {
            &mut input.signed_time_evidence
        });
        let path = write_input(root.path(), &input);
        assert!(prepare_with_clock(&path, &root.path().join("plan"), || Ok(
            common::EVIDENCE_TIME
        ))
        .is_err());
        assert!(!root.path().join("plan").exists());
        assert!(root.path().join("plan.preparing-v23").is_dir());
    }
}

#[test]
fn planning_refreshes_clock_before_publication_without_renewing_evidence() {
    for (start, finish) in [
        (common::EVIDENCE_TIME + 1, common::EVIDENCE_TIME + 300),
        (common::EVIDENCE_TIME + 2, common::EVIDENCE_TIME + 1),
    ] {
        let root = directory();
        let path = write_input(root.path(), &fixture());
        let mut calls = 0;
        let result = prepare_with_clock(&path, &root.path().join("plan"), || {
            calls += 1;
            Ok(if calls == 1 { start } else { finish })
        });
        assert!(result.is_err());
        assert_eq!(calls, 2);
        assert!(!root.path().join("plan").exists());
        assert!(root.path().join("plan.preparing-v23").is_dir());
        assert!(!root.path().join("plan.preparing-v23").join(REPORT).exists());
    }
}

#[test]
fn planning_does_not_overwrite_output_or_resume_incomplete_staging() {
    for existing in ["plan", "plan.preparing-v23"] {
        let root = directory();
        let retained = root.path().join(existing);
        fs::create_dir(&retained).unwrap();
        fs::write(retained.join("keep"), b"retained").unwrap();
        let path = write_input(root.path(), &fixture());
        assert!(matches!(
            prepare_with_clock(&path, &root.path().join("plan"), || Ok(
                common::EVIDENCE_TIME
            )),
            Err(PreparePlanningErrorV23::AlreadyPresent)
        ));
        assert_eq!(fs::read(retained.join("keep")).unwrap(), b"retained");
    }
}

#[test]
fn planning_refuses_input_links_broad_permissions_and_unknown_private_fields() {
    for mutation in 0..4 {
        let root = directory();
        let path = write_input(root.path(), &fixture());
        match mutation {
            0 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            1 => {
                fs::rename(&path, root.path().join("real")).unwrap();
                symlink("real", &path).unwrap();
            }
            2 => fs::hard_link(&path, root.path().join("alias")).unwrap(),
            _ => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["private_key"] = serde_json::json!("not-accepted");
                value["now_seconds"] = serde_json::json!(common::EVIDENCE_TIME);
                fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            }
        }
        assert!(prepare_with_clock(&path, &root.path().join("plan"), || Ok(
            common::EVIDENCE_TIME
        ))
        .is_err());
        assert!(!root.path().join("plan").exists());
        assert!(!root.path().join("plan.preparing-v23").exists());
    }
}

#[test]
fn planning_publication_refuses_directory_substitution() {
    let root = directory();
    let publication = Publication::create(&root.path().join("plan")).unwrap();
    fs::rename(
        root.path().join("plan.preparing-v23"),
        root.path().join("retained"),
    )
    .unwrap();
    symlink("retained", root.path().join("plan.preparing-v23")).unwrap();
    assert!(publication.publish().is_err());
    assert!(!root.path().join("plan").exists());
    assert!(root.path().join("retained").is_dir());
}

#[test]
fn planning_snapshots_file_sources_as_immutable_canonical_bytes() {
    let root = directory();
    let mut input = fixture();
    let ArtifactSource::CanonicalHex { hex } = &input.signed_registry else {
        panic!("inline registry");
    };
    let registry_path = root.path().join("signed-registry.bin");
    fs::write(&registry_path, hex::decode(hex).unwrap()).unwrap();
    fs::set_permissions(&registry_path, fs::Permissions::from_mode(0o600)).unwrap();
    input.signed_registry = ArtifactSource::File {
        path: registry_path,
    };
    let input_file = write_input(root.path(), &input);
    let output = root.path().join("plan");
    prepare_with_clock(&input_file, &output, || Ok(common::EVIDENCE_TIME)).unwrap();
    let snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join(SNAPSHOT)).unwrap()).unwrap();
    assert_eq!(snapshot["signed_registry"]["source"], "canonical_hex");
    assert!(snapshot["signed_registry"].get("path").is_none());
}
