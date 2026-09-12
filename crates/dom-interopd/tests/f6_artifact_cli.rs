#![cfg(feature = "production")]

use btc_crypto::SecpContext;
use deployment_registry::AuthoritySetV1;
use dom_interopd::{
    PreparedPublicF6ReportV23, ProductionAuthorityBundleV1, ProductionRelayRosterBundleV1,
    ProductionRosterLegV1, ProductionRosterMemberV1, ProductionRoutePositionV1,
};
use kaystra_core::terms::SettlementTermsV1;
use relay::SenderRoleV1;
use serde_json::{json, Value};
use std::{
    io::Write,
    os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn write_private(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    path
}

fn run_f6(arguments: &[&str]) -> Output {
    // This is Cargo's actual binary, never an in-process API fallback.
    Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
        .arg("prepare-f6-artifact-v23")
        .args(arguments)
        .output()
        .unwrap()
}

fn report(output: Output) -> PreparedPublicF6ReportV23 {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn refused(output: Output) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

fn public_fixture(secp: &SecpContext, root: &Path) -> Value {
    // Synthetic public artifacts only. Signing secrets stay in this parent
    // test process and are never supplied to the daemon child.
    let key = |n| secp.sign_bip340(&[n; 32], &[1; 32], &[2; 32]).unwrap().1;
    let inline = |bytes: Vec<u8>| json!({"source":"canonical_hex","hex":hex::encode(bytes)});
    let up = SettlementTermsV1::decode(
        &hex::decode(include_str!("../../kaystra-core/fixtures/terms-v1/valid-minimal.hex").trim())
            .unwrap(),
    )
    .unwrap();
    let mut down = up.clone();
    down.session_id.0[0] ^= 1;
    down.settlement_id.0[0] ^= 1;
    let authorities = ProductionAuthorityBundleV1::new(
        AuthoritySetV1::new(2, vec![key(10), key(11)]).unwrap(),
        AuthoritySetV1::new(1, vec![key(18)]).unwrap(),
        AuthoritySetV1::new(1, vec![key(19)]).unwrap(),
    )
    .unwrap();
    let bond = AuthoritySetV1::new(2, vec![key(12), key(13)]).unwrap();
    let status = AuthoritySetV1::new(2, vec![key(14), key(15)]).unwrap();
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
                    xonly_key: key(20 + j as u8),
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
    let signers: [Vec<Value>; 2] = std::array::from_fn(|i| {
        bond.xonly_keys()
            .iter()
            .enumerate()
            .map(|(j, k)| {
                json!({
                    "independent_authority_id":([30 + j as u8;32]), "signer_index":j,
                    "signer_public_key":k, "endpoint_uid":1000,
                    "endpoint":root.join(format!("absent-leg-{i}-signer-{j}.sock")),
                })
            })
            .collect()
    });
    let upstream = write_private(root, "upstream.bin", &up.canonical_bytes().unwrap());
    json!({
        "schema":"DOM-F6-PUBLIC-INPUT-V23",
        "route": {
            "network_id":([1;32]), "route_id":([2;32]), "composition_digest":([3;32]),
            "route_scope_digest":route_time_anchor::route_scope_digest(&up, &down).unwrap(),
            "registry_digest":([5;32]), "registry_epoch":1, "profile_bundle_digest":([6;32])
        },
        "economics": {
            "solver":([7;32]), "inventory_binding_digest":([8;32]), "bond_policy_hash":([9;32]),
            "bond_asset_binding_digest":([10;32]), "required_collateral":100,
            "status_max_lifetime_seconds":30, "valid_from_seconds":100,
            "expires_at_seconds":200, "max_evidence_age_seconds":10
        },
        "authorities":inline(authorities.canonical_bytes().unwrap()),
        "relay_roster":inline(roster.canonical_bytes().unwrap()),
        "upstream_terms":{"source":"file","path":upstream},
        "downstream_terms":inline(down.canonical_bytes().unwrap()),
        "bond_authorities":inline(bond.canonical_bytes().unwrap()),
        "status_authorities":inline(status.canonical_bytes().unwrap()),
        "reserved_participant_keys":[key(16)], "signers":signers,
        "claim_profile":{"profile":"native_enrollment"}
    })
}

#[test]
fn public_f6_cli_prepares_resumes_and_finalizes_external_signatures_without_signers() {
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let secp = SecpContext::new(&[74; 32]);
    let input = public_fixture(&secp, root.path());
    let input_path = write_private(
        root.path(),
        "input.json",
        &serde_json::to_vec(&input).unwrap(),
    );
    let request_path = root.path().join("request");
    let request = request_path.to_str().unwrap();
    let prepare = [
        "--input",
        input_path.to_str().unwrap(),
        "--output-dir",
        request,
    ];
    let prepared = report(run_f6(&prepare));
    assert!(!prepared.authenticated_authority);
    assert!(!prepared.finalized);
    assert_eq!(prepared.bundle_digest_hex, None);
    refused(run_f6(&prepare));
    let resume = ["--resume", "--request-dir", request];
    assert_eq!(report(run_f6(&resume)), prepared);
    // Freeze source independence across separate process invocations.
    std::fs::write(root.path().join("upstream.bin"), b"changed source").unwrap();
    assert_eq!(report(run_f6(&resume)), prepared);
    let prefix = std::fs::read(request_path.join("signing-prefix.bin")).unwrap();
    assert!(prefix.starts_with(b"DOMF6A23"));
    assert_eq!(prefix.len(), prepared.signing_prefix_bytes);
    let snapshot = std::fs::read(request_path.join("public-input.json")).unwrap();
    assert!(!String::from_utf8_lossy(&snapshot).contains("\"source\":\"file\""));
    let digest: [u8; 32] = hex::decode(&prepared.signing_digest_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let signed = |aux| {
        json!({
            "schema":"DOM-F6-EXTERNAL-SIGNATURES-V23",
            "signing_digest_hex":prepared.signing_digest_hex,
            "signatures":([0u8,1].map(|i| json!({"signer_index":i,
                "signature_hex":hex::encode(secp.sign_bip340(&[10+i;32], &digest, &[aux;32]).unwrap().0)})))
        })
    };
    let good = signed(75);
    let mut missing = good.clone();
    missing["signatures"].as_array_mut().unwrap().pop();
    let mut duplicated = good.clone();
    duplicated["signatures"][1] = duplicated["signatures"][0].clone();
    let mut wrong_digest = good.clone();
    wrong_digest["signing_digest_hex"] = json!(hex::encode([99; 32]));
    let mut wrong_key = good.clone();
    wrong_key["signatures"][1]["signature_hex"] = json!(hex::encode(
        secp.sign_bip340(&[77; 32], &digest, &[78; 32]).unwrap().0
    ));
    for (i, invalid) in [missing, duplicated, wrong_digest, wrong_key]
        .iter()
        .enumerate()
    {
        let path = write_private(
            root.path(),
            &format!("invalid-{i}.json"),
            &serde_json::to_vec(invalid).unwrap(),
        );
        refused(run_f6(&[
            "--finalize",
            "--request-dir",
            request,
            "--signatures",
            path.to_str().unwrap(),
        ]));
        assert!(!request_path.join("finalized").exists());
        assert!(!request_path.join("finalized.preparing-v23").exists());
        assert_eq!(report(run_f6(&resume)), prepared);
    }
    let signatures = write_private(
        root.path(),
        "signatures.json",
        &serde_json::to_vec(&good).unwrap(),
    );
    let finalize = [
        "--finalize",
        "--request-dir",
        request,
        "--signatures",
        signatures.to_str().unwrap(),
    ];
    let finalized = report(run_f6(&finalize));
    assert!(finalized.finalized);
    assert!(!finalized.authenticated_authority);
    assert_eq!(finalized.signing_digest_hex, prepared.signing_digest_hex);
    let bundle_path = request_path.join("finalized/authority.bundle");
    let bundle = std::fs::read(&bundle_path).unwrap();
    let mut expected = prefix;
    expected.extend_from_slice(&2u16.to_be_bytes());
    for (i, signature) in good["signatures"].as_array().unwrap().iter().enumerate() {
        expected.extend_from_slice(&(i as u16).to_be_bytes());
        expected
            .extend_from_slice(&hex::decode(signature["signature_hex"].as_str().unwrap()).unwrap());
    }
    assert_eq!(bundle, expected);
    assert_eq!(
        finalized.bundle_digest_hex,
        Some(hex::encode(
            dom_interopd::production_f6_authority_bundle_digest_v8(&bundle).unwrap()
        ))
    );
    let before = std::fs::metadata(&bundle_path).unwrap();
    assert_eq!(report(run_f6(&resume)), finalized);
    assert_eq!(report(run_f6(&finalize)), finalized);
    let different = write_private(
        root.path(),
        "different-valid-signatures.json",
        &serde_json::to_vec(&signed(76)).unwrap(),
    );
    refused(run_f6(&[
        "--finalize",
        "--request-dir",
        request,
        "--signatures",
        different.to_str().unwrap(),
    ]));
    let after = std::fs::metadata(&bundle_path).unwrap();
    assert_eq!(
        (before.ino(), before.mtime(), before.mtime_nsec()),
        (after.ino(), after.mtime(), after.mtime_nsec())
    );
    assert_eq!(std::fs::read(&bundle_path).unwrap(), bundle);
    for directory in [&request_path, &request_path.join("finalized")] {
        assert_eq!(std::fs::metadata(directory).unwrap().mode() & 0o7777, 0o700);
        for entry in std::fs::read_dir(directory).unwrap() {
            let metadata = entry.unwrap().metadata().unwrap();
            if metadata.is_file() {
                assert_eq!(metadata.mode() & 0o7777, 0o600);
                assert_eq!(metadata.nlink(), 1);
            }
        }
    }
    // Corruption is retained, never silently repaired by resume or finalize.
    let mut corrupted = bundle;
    *corrupted.last_mut().unwrap() ^= 1;
    std::fs::write(&bundle_path, &corrupted).unwrap();
    refused(run_f6(&resume));
    refused(run_f6(&finalize));
    assert_eq!(std::fs::read(bundle_path).unwrap(), corrupted);
    for leg in input["signers"].as_array().unwrap() {
        for signer in leg.as_array().unwrap() {
            assert!(!Path::new(signer["endpoint"].as_str().unwrap()).exists());
        }
    }
}

#[test]
fn public_f6_cli_exposes_all_offline_request_phases() {
    let output = Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
        .args(["prepare-f6-artifact-v23", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for option in [
        "--input",
        "--output-dir",
        "--resume",
        "--request-dir",
        "--finalize",
        "--signatures",
    ] {
        assert!(help.contains(option), "missing {option}");
    }
}

#[test]
fn public_f6_cli_refuses_missing_inputs_without_creating_or_repairing_outputs() {
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let missing = root.path().join("missing-public-input.json");
    let output = root.path().join("request");
    for arguments in [
        vec![
            "--input",
            missing.to_str().unwrap(),
            "--output-dir",
            output.to_str().unwrap(),
        ],
        vec!["--resume", "--request-dir", output.to_str().unwrap()],
        vec![
            "--finalize",
            "--request-dir",
            output.to_str().unwrap(),
            "--signatures",
            missing.to_str().unwrap(),
        ],
    ] {
        let refused = Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
            .arg("prepare-f6-artifact-v23")
            .args(arguments)
            .output()
            .unwrap();
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&refused.stderr).contains(root.path().to_str().unwrap()));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
    let alias = root.path().join("alias");
    symlink(&output, &alias).unwrap();
    let refused = Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
        .args(["prepare-f6-artifact-v23", "--resume", "--request-dir"])
        .arg(&alias)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(!output.exists());
    assert!(std::fs::symlink_metadata(&alias)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn public_f6_cli_refuses_ambiguous_or_incomplete_modes() {
    for arguments in [
        vec![],
        vec!["--resume"],
        vec!["--finalize", "--request-dir", "/unused"],
        vec!["--resume", "--finalize", "--request-dir", "/unused"],
        vec!["--input", "/unused", "--output-dir", "/unused", "--resume"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
            .arg("prepare-f6-artifact-v23")
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}
