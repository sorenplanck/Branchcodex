use super::*;
use crate::production_inputs::{
    ProductionRosterLegV1, ProductionRosterMemberV1, ProductionRoutePositionV1,
};
use relay::SenderRoleV1;
use std::os::unix::fs::PermissionsExt;

fn public_key(secp: &SecpContext, n: u8) -> [u8; 32] {
    secp.sign_bip340(&[n; 32], &[1; 32], &[2; 32]).unwrap().1
}
fn inline(bytes: Vec<u8>) -> ArtifactSource {
    ArtifactSource::CanonicalHex {
        hex: hex::encode(bytes),
    }
}
fn public_input(secp: &SecpContext) -> PublicInput {
    let up = SettlementTermsV1::decode(
        &hex::decode(include_str!("../../kaystra-core/fixtures/terms-v1/valid-minimal.hex").trim())
            .unwrap(),
    )
    .unwrap();
    let mut down = up.clone();
    down.session_id.0[0] ^= 1;
    down.settlement_id.0[0] ^= 1;
    let authorities = ProductionAuthorityBundleV1::new(
        AuthoritySetV1::new(2, vec![public_key(secp, 10), public_key(secp, 11)]).unwrap(),
        AuthoritySetV1::new(1, vec![public_key(secp, 18)]).unwrap(),
        AuthoritySetV1::new(1, vec![public_key(secp, 19)]).unwrap(),
    )
    .unwrap();
    let roster = ProductionRelayRosterBundleV1::new(
        [1; 32],
        [2; 32],
        std::array::from_fn(|i| {
            let terms = [&up, &down][i];
            ProductionRosterLegV1 {
                position: if i == 0 {
                    ProductionRoutePositionV1::Upstream
                } else {
                    ProductionRoutePositionV1::Downstream
                },
                session_id: terms.session_id.0,
                roster_snapshot: [40 + i as u8; 32],
                policy_version: terms.policy_version,
                members: std::array::from_fn(|j| ProductionRosterMemberV1 {
                    participant_id: terms.roster[j],
                    xonly_key: public_key(secp, 20 + j as u8),
                    role: if j == 0 {
                        SenderRoleV1::Initiator
                    } else {
                        SenderRoleV1::Solver
                    },
                }),
            }
        }),
    )
    .unwrap();
    let bond = AuthoritySetV1::new(2, vec![public_key(secp, 12), public_key(secp, 13)]).unwrap();
    let status = AuthoritySetV1::new(2, vec![public_key(secp, 14), public_key(secp, 15)]).unwrap();
    PublicInput {
        schema: INPUT_SCHEMA.into(),
        route: RoutePins {
            network_id: [1; 32],
            route_id: [2; 32],
            composition_digest: [3; 32],
            route_scope_digest: route_time_anchor::route_scope_digest(&up, &down).unwrap(),
            registry_digest: [5; 32],
            registry_epoch: 1,
            profile_bundle_digest: [6; 32],
        },
        economics: Economics {
            solver: [7; 32],
            inventory_binding_digest: [8; 32],
            bond_policy_hash: [9; 32],
            bond_asset_binding_digest: [10; 32],
            required_collateral: 100,
            status_max_lifetime_seconds: 30,
            valid_from_seconds: 100,
            expires_at_seconds: 200,
            max_evidence_age_seconds: 10,
        },
        authorities: inline(authorities.canonical_bytes().unwrap()),
        relay_roster: inline(roster.canonical_bytes().unwrap()),
        upstream_terms: inline(up.canonical_bytes().unwrap()),
        downstream_terms: inline(down.canonical_bytes().unwrap()),
        bond_authorities: inline(bond.canonical_bytes().unwrap()),
        status_authorities: inline(status.canonical_bytes().unwrap()),
        reserved_participant_keys: vec![public_key(secp, 16)],
        signers: std::array::from_fn(|i| {
            bond.xonly_keys()
                .iter()
                .enumerate()
                .map(|(j, key)| Signer {
                    independent_authority_id: [30 + j as u8; 32],
                    signer_index: j as u16,
                    signer_public_key: *key,
                    endpoint_uid: 1000,
                    endpoint: PathBuf::from(format!("/provided/leg-{i}/signer-{j}.sock")),
                })
                .collect()
        }),
        claim_profile: ClaimProfile::NativeEnrollment,
    }
}
fn private_temp() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    temp
}
fn put(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    write_new(&private_dir(root).unwrap(), name, bytes).unwrap();
    root.join(name)
}
fn signature_json(secp: &SecpContext, report: &PreparedPublicF6ReportV23) -> Vec<u8> {
    let digest: [u8; 32] = hex::decode(&report.signing_digest_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let signatures = (0u8..2)
        .map(|i| {
            serde_json::json!({
                "signer_index": i,
                "signature_hex": hex::encode(
                    secp.sign_bip340(&[10 + i; 32], &digest, &[45; 32])
                        .unwrap()
                        .0
                )
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&serde_json::json!({"schema":SIGNATURE_SCHEMA,
        "signing_digest_hex":report.signing_digest_hex,
        "signatures":signatures})).unwrap()
}

#[test]
fn public_f6_commands_prepare_snapshot_resume_and_finalize_exact_external_signatures() {
    let secp = SecpContext::new(&[46; 32]);
    let temp = private_temp();
    let mut input = public_input(&secp);
    // Prepare reads an actual existing public artifact, then freezes its bytes.
    let ArtifactSource::CanonicalHex { hex } = input.upstream_terms.clone() else {
        unreachable!()
    };
    let terms = put(temp.path(), "upstream.bin", &hex::decode(hex).unwrap());
    input.upstream_terms = ArtifactSource::File {
        path: terms.clone(),
    };
    let input_path = put(
        temp.path(),
        "input.json",
        &serde_json::to_vec(&input).unwrap(),
    );
    let directory = temp.path().join("request");
    let report = prepare_f6_artifact_command_v23(&input_path, &directory).unwrap();
    assert!(!report.authenticated_authority);
    assert!(!report.finalized);
    assert_eq!(resume_f6_artifact_command_v23(&directory).unwrap(), report);
    assert!(matches!(
        prepare_f6_artifact_command_v23(&input_path, &directory),
        Err(PrepareF6ArtifactErrorV23::AlreadyPresent)
    ));
    // Even corruption of the original source cannot change the frozen request.
    use std::os::unix::fs::FileExt;
    let original = std::fs::OpenOptions::new().write(true).open(terms).unwrap();
    original.write_all_at(b"X", 0).unwrap();
    original.sync_all().unwrap();
    assert_eq!(resume_f6_artifact_command_v23(&directory).unwrap(), report);
    let saved = read_file(&private_dir(&directory).unwrap(), SNAPSHOT, LIMIT).unwrap();
    assert!(!std::str::from_utf8(&saved)
        .unwrap()
        .contains("\"source\":\"file\""));
    let signatures = put(
        temp.path(),
        "signatures.json",
        &signature_json(&secp, &report),
    );
    let final_report = finalize_f6_artifact_command_v23(&directory, &signatures).unwrap();
    assert!(final_report.finalized);
    assert!(!final_report.authenticated_authority);
    assert!(final_report.bundle_digest_hex.is_some());
    assert_eq!(
        resume_f6_artifact_command_v23(&directory).unwrap(),
        final_report
    );
    assert_eq!(
        finalize_f6_artifact_command_v23(&directory, &signatures).unwrap(),
        final_report
    );
    let bundle_path = directory.join(FINAL).join(BUNDLE);
    let mut corrupted = std::fs::read(&bundle_path).unwrap();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    let output = std::fs::OpenOptions::new()
        .write(true)
        .open(&bundle_path)
        .unwrap();
    output
        .write_all_at(&corrupted[last..], last as u64)
        .unwrap();
    output.sync_all().unwrap();
    assert!(matches!(
        resume_f6_artifact_command_v23(&directory),
        Err(PrepareF6ArtifactErrorV23::RetainedRequest)
    ));
    assert_eq!(std::fs::read(bundle_path).unwrap(), corrupted);
}

#[test]
fn public_f6_commands_reject_missing_signatures_and_retained_crash_staging() {
    let secp = SecpContext::new(&[47; 32]);
    let temp = private_temp();
    let input = put(
        temp.path(),
        "input.json",
        &serde_json::to_vec(&public_input(&secp)).unwrap(),
    );
    let directory = temp.path().join("request");
    let report = prepare_f6_artifact_command_v23(&input, &directory).unwrap();
    let missing = put(
        temp.path(),
        "missing.json",
        &serde_json::to_vec(&serde_json::json!({
        "schema":SIGNATURE_SCHEMA,"signing_digest_hex":report.signing_digest_hex,"signatures":[]}))
        .unwrap(),
    );
    assert!(matches!(
        finalize_f6_artifact_command_v23(&directory, &missing),
        Err(PrepareF6ArtifactErrorV23::Signatures)
    ));
    assert!(!directory.join(FINAL).exists());
    let staging = Publication::under(private_dir(&directory).unwrap(), FINAL.into()).unwrap();
    write_new(&staging.staging, BUNDLE, b"incomplete retained output").unwrap();
    drop(staging);
    let before = std::fs::read(directory.join("finalized.preparing-v23").join(BUNDLE)).unwrap();
    assert!(matches!(
        resume_f6_artifact_command_v23(&directory),
        Err(PrepareF6ArtifactErrorV23::AlreadyPresent)
    ));
    assert_eq!(
        std::fs::read(directory.join("finalized.preparing-v23").join(BUNDLE)).unwrap(),
        before
    );
}

#[test]
fn public_f6_commands_refuse_changed_prefix_and_public_scope_before_publication() {
    let secp = SecpContext::new(&[48; 32]);
    let temp = private_temp();
    let mut input = public_input(&secp);
    input.route.route_id[0] ^= 1;
    let wrong = put(
        temp.path(),
        "wrong.json",
        &serde_json::to_vec(&input).unwrap(),
    );
    let directory = temp.path().join("request");
    assert!(matches!(
        prepare_f6_artifact_command_v23(&wrong, &directory),
        Err(PrepareF6ArtifactErrorV23::Input)
    ));
    assert!(!directory.exists());
    let good = put(
        temp.path(),
        "good.json",
        &serde_json::to_vec(&public_input(&secp)).unwrap(),
    );
    prepare_f6_artifact_command_v23(&good, &directory).unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(directory.join(PREFIX))
        .unwrap();
    use std::os::unix::fs::FileExt;
    file.write_all_at(b"X", 0).unwrap();
    file.sync_all().unwrap();
    let before = std::fs::read(directory.join(PREFIX)).unwrap();
    assert!(matches!(
        resume_f6_artifact_command_v23(&directory),
        Err(PrepareF6ArtifactErrorV23::RetainedRequest)
    ));
    assert_eq!(std::fs::read(directory.join(PREFIX)).unwrap(), before);
}

#[test]
fn public_f6_commands_refuse_unsafe_retained_files_without_repair() {
    let secp = SecpContext::new(&[49; 32]);
    for mutation in [
        "permissions",
        "hardlink",
        "symlink",
        "unexpected-file",
        "oversized",
    ] {
        let temp = private_temp();
        let input = put(
            temp.path(),
            "input.json",
            &serde_json::to_vec(&public_input(&secp)).unwrap(),
        );
        let directory = temp.path().join("request");
        let report = prepare_f6_artifact_command_v23(&input, &directory).unwrap();
        let prefix = directory.join(PREFIX);
        let original = std::fs::read(&prefix).unwrap();
        match mutation {
            "permissions" => {
                std::fs::set_permissions(&prefix, std::fs::Permissions::from_mode(0o644)).unwrap()
            }
            "hardlink" => {
                std::fs::hard_link(&prefix, temp.path().join("linked-prefix.bin")).unwrap()
            }
            "symlink" => {
                std::fs::rename(&prefix, temp.path().join("moved-prefix.bin")).unwrap();
                std::os::unix::fs::symlink(temp.path().join("moved-prefix.bin"), &prefix).unwrap();
            }
            "unexpected-file" => {
                put(&directory, "unrecognized-input.json", b"{}");
            }
            "oversized" => std::fs::write(&prefix, vec![b'X'; 32_769]).unwrap(),
            _ => unreachable!(),
        }
        let before = std::fs::read(&prefix).unwrap();
        let signatures = put(
            temp.path(),
            "signatures.json",
            &signature_json(&secp, &report),
        );
        assert!(
            resume_f6_artifact_command_v23(&directory).is_err(),
            "{mutation}"
        );
        assert!(
            finalize_f6_artifact_command_v23(&directory, &signatures).is_err(),
            "{mutation}"
        );
        assert!(!directory.join(FINAL).exists(), "{mutation}");
        assert!(
            !directory.join("finalized.preparing-v23").exists(),
            "{mutation}"
        );
        assert_eq!(std::fs::read(&prefix).unwrap(), before, "{mutation}");
        if mutation != "oversized" {
            assert_eq!(before, original);
        }
    }
}
