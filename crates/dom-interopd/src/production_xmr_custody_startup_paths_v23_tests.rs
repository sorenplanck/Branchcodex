//! Startup path classification only; no provisioning or funding capability.
use super::*;
use crate::production_universal_leg_authority::ProductionResourceLeafV23 as Leaf;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};

fn private_root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private root")
}

#[test]
fn only_native_custody_leaf_can_be_absent() {
    let root = private_root();
    let leaf = root.path().join("graph-custody");
    assert!(require_selected_parent_chain_v11(
        root.path(),
        &leaf,
        Leaf::NativeXmrGraphCustodyDirectory
    )
    .is_ok());
    assert!(require_selected_parent_chain_v11(root.path(), &leaf, Leaf::Existing).is_err());
    assert!(!leaf.exists(), "preflight never creates custody");
}

#[test]
fn provisionable_leaf_cannot_hide_missing_parent_symlink_or_file() {
    let root = private_root();
    assert!(require_selected_parent_chain_v11(
        root.path(),
        &root.path().join("missing/custody"),
        Leaf::NativeXmrGraphCustodyDirectory
    )
    .is_err());
    let wrong = root.path().join("wrong-file");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&wrong)
        .expect("file");
    assert!(require_selected_parent_chain_v11(
        root.path(),
        &wrong,
        Leaf::NativeXmrGraphCustodyDirectory
    )
    .is_err());
    assert!(require_selected_parent_chain_v11(root.path(), &wrong, Leaf::Existing).is_ok());
    let link = root.path().join("custody-link");
    symlink(root.path().join("absent-target"), &link).expect("dangling symlink");
    assert!(require_selected_parent_chain_v11(
        root.path(),
        &link,
        Leaf::NativeXmrGraphCustodyDirectory
    )
    .is_err());
    assert!(require_selected_parent_chain_v11(root.path(), &link, Leaf::Existing).is_err());
}

#[test]
fn two_positions_cannot_reserve_the_same_absent_custody() {
    let root = private_root();
    let leaf = root.path().join("graph-custody");
    let extras = [
        (leaf.clone(), Leaf::NativeXmrGraphCustodyDirectory),
        (leaf.clone(), Leaf::NativeXmrGraphCustodyDirectory),
    ];
    assert!(require_selected_resource_paths_v23(root.path(), &extras, &mut Vec::new()).is_err());
    assert!(!leaf.exists());
    let separate = [
        (leaf, Leaf::NativeXmrGraphCustodyDirectory),
        (
            root.path().join("other-custody"),
            Leaf::NativeXmrGraphCustodyDirectory,
        ),
    ];
    assert!(require_selected_resource_paths_v23(root.path(), &separate, &mut Vec::new()).is_ok());
}

#[test]
fn custody_startup_rejects_a_nonprivate_root() {
    let root = private_root();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(require_selected_parent_chain_v11(
        root.path(),
        &root.path().join("custody"),
        Leaf::NativeXmrGraphCustodyDirectory,
    )
    .is_err());
}
