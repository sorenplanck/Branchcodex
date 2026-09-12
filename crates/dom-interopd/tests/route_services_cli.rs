#![cfg(feature = "production")]

use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output, Stdio};

const FILE: &str = "production-route-services.v8.json";
const STAGING: &str = ".production-route-services.v8.json.preparing-v11";

fn private_root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn request(upstream: &str, downstream: &str) -> Value {
    let service = |family: &str| match family {
        "BTC" => json!({"family": "BTC", "endpoint": "http://127.0.0.1:18443",
            "wallet": "operator-selected", "cookie": "/unopened-bitcoin-cookie/absent"}),
        "EVM" => json!({"family": "EVM", "endpoint": "http://127.0.0.1:18545",
            "refund_timeout_seconds": 30}),
        family => json!({"family": family, "endpoints": ["http://127.0.0.1:18081"], "quorum": 1}),
    };
    json!({
        "version": 8, "route_id": vec![1u8; 32],
        "composition_digest": vec![2u8; 32], "registry_digest": vec![3u8; 32],
        "legs": [
            {"settlement_id": vec![4u8; 32], "chain_id": vec![5u8; 32], "service": service(upstream)},
            {"settlement_id": vec![6u8; 32], "chain_id": vec![7u8; 32], "service": service(downstream)}
        ]
    })
}

fn run(root: &Path, bytes: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dom-interopd"))
        .args(["prepare-route-services-v11", "--state-dir"])
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn cli_publishes_all_sixteen_public_pairs_without_rpc_or_cookie_access() {
    for upstream in ["BTC", "EVM", "SOL", "XMR"] {
        for downstream in ["BTC", "EVM", "SOL", "XMR"] {
            let root = private_root();
            let input = request(upstream, downstream);
            let result = run(root.path(), &serde_json::to_vec_pretty(&input).unwrap());
            assert!(result.status.success(), "{:?}", result.stderr);
            assert!(result.stderr.is_empty());
            let report: Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(report["file"], FILE);
            assert_eq!(report["positions"], 2);
            assert_eq!(report["network_access"], false);
            assert!(!String::from_utf8(result.stdout)
                .unwrap()
                .contains("127.0.0.1"));
            let path = root.path().join(FILE);
            let canonical = std::fs::read(&path).unwrap();
            assert_eq!(report["bytes"], canonical.len());
            assert_eq!(serde_json::from_slice::<Value>(&canonical).unwrap(), input);
            assert!(canonical.ends_with(b"\n"));
            assert_eq!(canonical.iter().filter(|b| **b == b'\n').count(), 1);
            let metadata = std::fs::metadata(&path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(
                metadata.uid(),
                std::fs::metadata(root.path()).unwrap().uid()
            );
            assert!(!root.path().join(STAGING).exists());
            assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
            // Re-running, even with identical content, never overwrites custody.
            assert!(!run(root.path(), &canonical).status.success());
            assert_eq!(std::fs::read(&path).unwrap(), canonical);
            assert!(!root.path().join(STAGING).exists());
        }
    }
}

#[test]
fn cli_refuses_invalid_secret_bearing_oversized_or_ambiguous_input_before_publication() {
    let baseline = request("SOL", "XMR");
    let mut secret = baseline.clone();
    secret["legs"][0]["service"]["seed"] = json!("DO-NOT-ECHO-SECRET");
    let mut authenticated_url = baseline.clone();
    authenticated_url["legs"][1]["service"]["endpoints"][0] =
        json!("http://operator:DO-NOT-ECHO-SECRET@127.0.0.1:18081");
    let mut unknown = baseline.clone();
    unknown["legs"][0]["service"]["family"] = json!("DOM");
    let mut aliased = baseline.clone();
    aliased["legs"][1]["settlement_id"] = aliased["legs"][0]["settlement_id"].clone();
    for bytes in [
        vec![],
        vec![b'x'; 131_073],
        b"{}".to_vec(),
        serde_json::to_vec(&secret).unwrap(),
        serde_json::to_vec(&authenticated_url).unwrap(),
        serde_json::to_vec(&unknown).unwrap(),
        serde_json::to_vec(&aliased).unwrap(),
        serde_json::to_string(&baseline)
            .unwrap()
            .replacen("\"version\":8", "\"version\":8,\"version\":8", 1)
            .into_bytes(),
    ] {
        let root = private_root();
        let result = run(root.path(), &bytes);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8(result.stderr)
            .unwrap()
            .contains("DO-NOT-ECHO-SECRET"));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn cli_preserves_existing_symlinks_hardlinks_and_interrupted_staging() {
    let bytes = serde_json::to_vec(&request("XMR", "XMR")).unwrap();
    for reserved in [FILE, STAGING] {
        for kind in ["file", "symlink", "hardlink"] {
            let root = private_root();
            let source = root.path().join("retained");
            std::fs::write(&source, b"retain original bytes").unwrap();
            let destination = root.path().join(reserved);
            match kind {
                "symlink" => symlink("retained", &destination).unwrap(),
                "hardlink" => std::fs::hard_link(&source, &destination).unwrap(),
                _ => std::fs::write(&destination, b"interrupted preparation").unwrap(),
            }
            let before = std::fs::read(&destination).unwrap();
            let result = run(root.path(), &bytes);
            assert!(!result.status.success());
            assert_eq!(std::fs::read(&destination).unwrap(), before);
            assert_eq!(std::fs::read(&source).unwrap(), b"retain original bytes");
            assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
        }
    }
}

#[test]
fn cli_refuses_malformed_https_before_publication() {
    for endpoint in ["https://:443", "https://host:99999", "https://[::1"] {
        let root = private_root();
        let mut input = request("SOL", "XMR");
        input["legs"][0]["service"]["endpoints"][0] = json!(endpoint);
        let result = run(root.path(), &serde_json::to_vec(&input).unwrap());
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn cli_refuses_nonprivate_and_symlinked_state_directories() {
    let bytes = serde_json::to_vec(&request("SOL", "SOL")).unwrap();
    let root = private_root();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!run(root.path(), &bytes).status.success());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let parent = private_root();
    let alias = parent.path().join("alias");
    symlink(root.path(), &alias).unwrap();
    assert!(!run(&alias, &bytes).status.success());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
