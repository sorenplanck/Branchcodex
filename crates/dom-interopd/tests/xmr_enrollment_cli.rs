#![cfg(feature = "production")]

use serde_json::json;
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output, Stdio},
};

fn run(root: &Path, bytes: &[u8], reopen: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dom-interopd"));
    command
        .args(["prepare-xmr-enrollment-v23", "--state-dir"])
        .arg(root)
        .args(["--position", "upstream", "--output-dir"])
        .arg(root.join("custody"));
    if reopen {
        command.arg("--reopen");
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn enrollment_cli_help_describes_offline_custody_not_funding() {
    let output = Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
        .args(["prepare-xmr-enrollment-v23", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for required in [
        "4096",
        "--reopen",
        "does not authorize funding",
        "Role is derived",
        "nullifiers.sqlite",
    ] {
        assert!(help.contains(required), "{required}");
    }
}

#[test]
fn enrollment_cli_refuses_invalid_secrets_and_missing_context_without_state_mutations() {
    let valid = json!({"schema":"DOM-XMR-ENROLLMENT-V23", "local_participant_id":vec![1u8;32],
        "master_key_hex":"03".repeat(32), "spend_share_le_hex":"07".repeat(32), "view_key_le_hex":"09".repeat(32)});
    let mut extra = valid.clone();
    extra["remote_spend_share"] = json!("DO-NOT-ECHO-SECRET");
    let mut invalid = valid.clone();
    invalid["master_key_hex"] = json!("DO-NOT-ECHO-SECRET");
    for (bytes, reopen) in [
        (vec![], false),
        (vec![b'x'; 4097], false),
        (b"{}".to_vec(), false),
        (serde_json::to_vec(&valid).unwrap(), false),
        (serde_json::to_vec(&valid).unwrap(), true),
        (serde_json::to_vec(&extra).unwrap(), false),
        (serde_json::to_vec(&invalid).unwrap(), false),
    ] {
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let output = run(root.path(), &bytes, reopen);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(!error.contains("DO-NOT-ECHO-SECRET"));
        assert!(!error.contains(&"03".repeat(32)));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn enrollment_cli_rejects_escaped_private_input_before_loading_context() {
    let input = json!({"schema":"DOM-XMR-ENROLLMENT-V23", "local_participant_id":vec![1u8;32],
        "master_key_hex":"03".repeat(32), "spend_share_le_hex":"07".repeat(32), "view_key_le_hex":"09".repeat(32)});
    for field in ["master_key_hex", "spend_share_le_hex", "view_key_le_hex"] {
        let text = serde_json::to_string(&input).unwrap();
        let original = input[field].as_str().unwrap();
        let escaped = text.replace(original, &format!(r"\u0030{}", &original[1..]));
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let output = run(root.path(), escaped.as_bytes(), false);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "invalid bounded enrollment credentials"
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn enrollment_cli_preserves_existing_private_key_separation_policy() {
    for pair in [
        ["master_key_hex", "spend_share_le_hex"],
        ["master_key_hex", "view_key_le_hex"],
        ["spend_share_le_hex", "view_key_le_hex"],
    ] {
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut input = json!({"schema":"DOM-XMR-ENROLLMENT-V23", "local_participant_id":vec![1u8;32],
            "master_key_hex":"03".repeat(32), "spend_share_le_hex":"07".repeat(32), "view_key_le_hex":"09".repeat(32)});
        input[pair[1]] = input[pair[0]].clone();
        let output = run(root.path(), &serde_json::to_vec(&input).unwrap(), false);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "invalid bounded enrollment credentials"
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
