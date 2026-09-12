#![cfg(feature = "production")]
use serde_json::json;
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
};

#[test]
fn xmr_leg_cli_documents_non_authorizing_offline_publication() {
    let output = Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
        .args(["prepare-xmr-leg-v23", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for field in [
        "16384",
        "compensation_policy",
        "authority_bundle_digest",
        "no default",
        "does not rewrite",
        "no F6",
    ] {
        assert!(help.contains(field), "missing {field}");
    }
}

#[test]
fn xmr_leg_cli_refuses_unbounded_secret_bearing_or_invalid_public_inputs_without_writes() {
    let request = json!({"schema":"DOM-XMR-LEG-V23","compensation_policy":[],"resources":{
        "local_participant_id":vec![1u8;32],"secret_store":"enrollment/secrets.sqlite","nullifier_store":"enrollment/nullifiers.sqlite",
        "sidecar_socket":"sidecar/xmr.sock","sidecar_timeout_ms":1000,"custody_directory":"graph-custody",
        "sealing_key_file":"keys/graph.key","custody_id":vec![2u8;32]}});
    let mut secret = request.clone();
    secret["resources"]["sealing_key_hex"] = json!("DO-NOT-ECHO-SECRET");
    for bytes in [
        vec![],
        vec![b'x'; 16385],
        b"{}".to_vec(),
        serde_json::to_vec(&request).unwrap(),
        serde_json::to_vec(&secret).unwrap(),
        serde_json::to_string(&request)
            .unwrap()
            .replacen(
                "\"compensation_policy\":[]",
                "\"compensation_policy\":[],\"compensation_policy\":[]",
                1,
            )
            .into_bytes(),
    ] {
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
            .args(["prepare-xmr-leg-v23", "--state-dir"])
            .arg(root.path())
            .args(["--position", "upstream", "--output-file"])
            .arg(root.path().join("leg.json"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8(output.stderr)
            .unwrap()
            .contains("DO-NOT-ECHO-SECRET"));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
