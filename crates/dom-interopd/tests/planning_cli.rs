#![cfg(all(feature = "production", target_os = "linux"))]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn planning_cli_exposes_the_offline_production_writer() {
    let output = Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
        .args(["prepare-planning-v23", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--input"));
    assert!(help.contains("--output-dir"));
    assert!(help.contains("No private keys"));
}

#[test]
fn planning_cli_rejects_ambiguous_modes_without_creating_state() {
    for arguments in [
        vec!["prepare-planning-v23"],
        vec!["prepare-planning-v23", "--resume"],
        vec!["prepare-planning-v23", "--input", "relative"],
        vec!["prepare-planning-v23", "--now", "1"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
    }
}

#[test]
fn planning_cli_missing_input_never_creates_output_or_repairs_staging() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let missing = root.path().join("missing.json");
    let output = root.path().join("plan");
    let result = Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
        .arg("prepare-planning-v23")
        .arg("--input")
        .arg(&missing)
        .arg("--output-dir")
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(!output.exists());
    assert!(!root.path().join("plan.preparing-v23").exists());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
