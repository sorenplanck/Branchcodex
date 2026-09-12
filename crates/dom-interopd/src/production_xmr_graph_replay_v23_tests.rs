//! Opt-in diagnosis of an existing, owner-only failed fixture. No ceremony,
//! signing, repair, provisioning or missing-artifact creation is performed.
use super::*;
#[path = "production_xmr_graph_binding_replay_v23_tests.rs"]
mod binding_replay_v23_tests;

fn require_fixture_path(root: &Path, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_absolute()
        || !path.starts_with(root)
        || std::fs::canonicalize(path)?.as_path() != path
        || std::fs::symlink_metadata(path)?.file_type().is_symlink()
    {
        return Err("replay path is outside the fixture or traverses a symlink".into());
    }
    Ok(())
}

#[test]
#[ignore = "requires explicit owner-only DOM_XMR_REPLAY_FIXTURE_V23; does not regenerate C/D"]
fn v23_preflight_preserved_graph_fixture_read_only() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(
        std::env::var_os("DOM_XMR_REPLAY_FIXTURE_V23")
            .ok_or("set DOM_XMR_REPLAY_FIXTURE_V23 to the exact retained fixture")?,
    );
    // Checks canonical absolute path, all symlink components, owner UID and 0700.
    let _root_capability = private_directory(&root)
        .map_err(|error| format!("replay fixture root validation: {error}"))?;
    let mut contexts = Vec::new();
    let mut plans = Vec::new();
    for (actor, name) in ["alice-plan.json", "bob-plan.json"].into_iter().enumerate() {
        let path = root.join(name);
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
        // The pinned registry signature authenticates the genesis/runtime ID;
        // never turn a retained graph checksum or chain digest into trust.
        let context = load_context(&plan, &SecpContext::new(&[13; 32]), true)
            .map_err(|error| format!("replay authenticate-plan actor={actor}: {error}"))?;
        contexts.push(context);
        plans.push(plan);
    }
    if contexts[0].chain.as_bytes() != contexts[1].chain.as_bytes()
        || contexts[0].expected.route_id != contexts[1].expected.route_id
        || contexts[0].bindings[0][0].session_id() != contexts[1].bindings[0][0].session_id()
    {
        return Err("replay actors disagree on authenticated chain/route/session".into());
    }
    for (actor, directory) in ["alice", "bob"].into_iter().enumerate() {
        let work = root.join(directory);
        let capability = private_directory(&work)
            .map_err(|error| format!("replay actor-directory actor={actor}: {error}"))?;
        let context = &contexts[actor];
        let participant = context.rosters.legs()[0]
            .members
            .iter()
            .position(|member| member.participant_id.0 == plans[actor].local_participant_id)
            .ok_or("replay authenticated roster lacks local participant")?;
        let budget = BudgetPolicyV1::from_bytes(&bounded_owner_read(
            &plans[actor].budget_policy_file,
            dom_scriptless_store::BUDGET_POLICY_LEN as u64,
        )?)?;
        for (scope, name) in [
            ("parent", "runtime-contracts".to_string()),
            ("cancelled", format!("cancelled-contracts-{participant}")),
        ] {
            eprintln!("graph replay prepare-open actor={actor} scope={scope}");
            let prepared = dom_scriptless_store::ContractsSessionStoreV1::prepare_open_production_with_trusted_chain_v23(
                Arc::clone(&capability), &name, budget.clone(), context.chain,
            ).map_err(|error| format!("graph replay prepare-open actor={actor} scope={scope}: {error}"))?;
            // Deliberately never finish(): recovery may promote staging or
            // restore successors. Keeping this handle only performs preflight.
            drop(prepared);
            eprintln!("graph replay read-only preflight passed actor={actor} scope={scope}");
        }
    }
    Ok(())
}
