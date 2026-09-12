//! Reproduce only GraphU binding admission on a private copy of a failed
//! fixture. This is not a signing test and never opens the original live Store.
use super::*;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

fn copy_private_tree(
    source: &Path,
    destination: &Path,
    depth: usize,
    entries: &mut usize,
    remaining: &mut u64,
) -> Result<(), Box<dyn std::error::Error>> {
    if depth > 8 {
        return Err("replay copy depth exceeded".into());
    }
    let _source_cap = private_directory(source)?;
    std::fs::create_dir(destination)?;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700))?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        *entries += 1;
        if *entries > 4096 {
            return Err("replay copy entry budget exceeded".into());
        }
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let named = std::fs::symlink_metadata(&source_path)?;
        if named.uid() != rustix::process::getuid().as_raw() || named.file_type().is_symlink() {
            return Err("replay copy foreign owner or symlink".into());
        }
        if named.is_dir() {
            copy_private_tree(
                &source_path,
                &destination_path,
                depth + 1,
                entries,
                remaining,
            )?;
            continue;
        }
        if !named.is_file()
            || named.nlink() != 1
            || named.mode() & 0o7777 != 0o600
            || named.len() > 64 * 1024 * 1024
            || named.len() > *remaining
        {
            return Err("replay copy invalid file or byte budget exceeded".into());
        }
        let input = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&source_path)?;
        let opened = input.metadata()?;
        if opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.len() != named.len()
            || opened.nlink() != 1
        {
            return Err("replay copy source changed before opening".into());
        }
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(destination_path)?;
        let copied = std::io::copy(&mut input.take(named.len() + 1), &mut output)?;
        let after = std::fs::symlink_metadata(&source_path)?;
        if copied != named.len()
            || after.dev() != named.dev()
            || after.ino() != named.ino()
            || after.len() != named.len()
            || after.mtime() != named.mtime()
            || after.mtime_nsec() != named.mtime_nsec()
            || after.nlink() != 1
        {
            return Err("replay copy source changed during copying".into());
        }
        output.sync_all()?;
        *remaining -= copied;
    }
    Ok(())
}

#[test]
#[ignore = "explicit DOM_XMR_REPLAY_FIXTURE_V23; prepares only GraphU binding on a disposable copy"]
fn v23_replay_refund_adaptor_binding_on_private_copy() -> Result<(), Box<dyn std::error::Error>> {
    use dom_adaptor::AcceptedSigningSessionV1;
    use dom_scriptless_store::{
        ContractsSessionStoreV1, SessionPhaseV1, XmrGraphRecoverySigningEdgeV23 as Edge,
    };
    let root = PathBuf::from(
        std::env::var_os("DOM_XMR_REPLAY_FIXTURE_V23")
            .ok_or("set DOM_XMR_REPLAY_FIXTURE_V23 to the retained fixture")?,
    );
    let _root_cap = private_directory(&root)?;
    let path = root.join("alice-plan.json");
    require_fixture_path(&root, &path)?;
    let plan: Plan = serde_json::from_slice(&bounded_owner_read(&path, 65_536)?)?;
    for path in [
        &plan.authority_bundle_file,
        &plan.registry_store,
        &plan.roster_file,
        &plan.identity_store,
        &plan.budget_policy_file,
        &plan.terms_files[0],
        &plan.terms_files[1],
    ] {
        require_fixture_path(&root, path)?;
    }
    if let Some(paths) = &plan.xmr_compensation_policy_files {
        for path in paths.iter().flatten() {
            require_fixture_path(&root, path)?;
        }
    }
    let context = load_context(&plan, &SecpContext::new(&[13; 32]), true)
        .map_err(|error| format!("binding replay authenticate-plan: {error}"))?;
    let session = context.bindings[0][0].session_id();
    let budget = BudgetPolicyV1::from_bytes(&bounded_owner_read(
        &plan.budget_policy_file,
        dom_scriptless_store::BUDGET_POLICY_LEN as u64,
    )?)?;
    let source = root.join("alice/runtime-contracts");
    require_fixture_path(&root, &source)?;
    let original_binding = source.join("session-rosters").join(format!(
        "{}-03.xmr-graph-signing-session-v23",
        hex::encode(session)
    ));
    match std::fs::symlink_metadata(&original_binding) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => {
            return Err(
                "binding replay requires the original failed prefix without a U binding".into(),
            )
        }
    }
    let copied_root = tempfile::tempdir()?;
    std::fs::set_permissions(copied_root.path(), std::fs::Permissions::from_mode(0o700))?;
    copy_private_tree(
        &source,
        &copied_root.path().join("runtime-contracts"),
        0,
        &mut 0,
        &mut (256 * 1024 * 1024),
    )?;
    let store = ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
        private_directory(copied_root.path())?,
        "runtime-contracts",
        budget,
        context.chain,
    )
    .map_err(|error| format!("binding replay copied-store open: {error}"))?;
    let before = store.load_session(session)?;
    assert_eq!(before.revision(), 19);
    assert_eq!(before.phase(), SessionPhaseV1::TemplatesCommitted);
    let digest = store
        .prepare_xmr_graph_signing_session_v23(session, Edge::RefundAdaptor)
        .map_err(|error| format!("binding replay prepare U: {error}"))?;
    assert_ne!(digest, [0; 32]);
    let accepted = store
        .resume_xmr_graph_signing_session_v23(session, Edge::RefundAdaptor)
        .map_err(|error| format!("binding replay resume U: {error}"))?;
    assert_eq!(accepted.accepted_signing_messages().count(), 0);
    let after = store.load_session(session)?;
    assert_eq!(after.as_bytes(), before.as_bytes());
    assert!(!after.irreversible().funding_authorized);
    assert!(!after.irreversible().any_signing_share_sent);
    assert!(!after.irreversible().adaptor_secret_exposed);
    assert!(matches!(std::fs::symlink_metadata(&original_binding),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound));
    eprintln!("GraphU binding prepared and resumed on private copy; zero signing messages, original unchanged");
    Ok(())
}
