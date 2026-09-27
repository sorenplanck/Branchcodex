//! Provision one laboratory route to disk, with the ceremony's plans and secrets beside it.
//!
//! This exists because the Contracts bootstrap ceremony is a COMMAND, not a library call:
//! `dom-interopd bootstrap-v13` reads a plan from a path and secrets from stdin, and must be
//! run once per party with the peer's published packets copied across in between. A test
//! harness cannot hand it any of that; a program can.
//!
//! Usage:
//!
//! ```text
//! provision_route <state-dir> <provisioning-dir> <ceremony-dir>
//! ```
//!
//! The state directory receives everything the daemon's layout declares. The provisioning
//! directory receives what it does not -- the leg's setup store and the throwaway store the
//! time ladder is proved in -- and must not be inside the state directory, because the
//! layout refuses a managed path that already exists. The ceremony directory receives the
//! two plans and the two secrets files.
//!
//! What it prints, on one line each: the state directory, then every path the next step
//! needs. Nothing secret is printed; the secrets are written owner-only to files, because
//! the ceremony reads them from stdin and a shell that echoes them would put them in a log.

use std::path::PathBuf;

use dom_solana_daemon_route::{ceremony, laboratory};

fn main() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [state_dir, provisioning_dir, ceremony_dir] = arguments.as_slice() else {
        return Err(
            "usage: provision_route <state-dir> <provisioning-dir> <ceremony-dir>".to_owned(),
        );
    };
    let state_dir = PathBuf::from(state_dir);
    let provisioning_dir = PathBuf::from(provisioning_dir);
    let ceremony_dir = PathBuf::from(ceremony_dir);

    // The ceremony resolves the plan's paths in its own process, so they must be absolute.
    // Canonical too: the daemon's own loader refuses a state directory whose canonical form
    // differs from itself, and a plan naming a non-canonical path would name a second name
    // for the same file.
    dom_solana_daemon_route::owner_only::directory(&state_dir)?;
    let state_dir = state_dir
        .canonicalize()
        .map_err(|error| format!("canonicalize the state directory: {error}"))?;

    // The REAL clock, because the ceremony validates the registry with SystemTime::now()
    // rather than with a trusted second from the plan. A route anchored on a fictional time
    // is refused there as not yet valid.
    let now_seconds = laboratory::now_seconds()?;
    let route = laboratory::provision(&state_dir, &provisioning_dir, now_seconds)?;
    let plans = ceremony::write_plans(&route.ceremony_input(&state_dir), &ceremony_dir)?;
    let secrets: [PathBuf; 2] = [
        ceremony::write_secrets(
            &route.parties[0].0,
            laboratory::IDENTITY_PASSPHRASE,
            &ceremony_dir,
            "secrets-party-0.json",
        )?,
        ceremony::write_secrets(
            &route.parties[1].0,
            laboratory::IDENTITY_PASSPHRASE,
            &ceremony_dir,
            "secrets-party-1.json",
        )?,
    ];

    // The plan, so the admission step can carry the pins instead of recomputing them:
    // provisioning generates a fresh condition scalar, so a rebuild would freeze different
    // terms with different digests.
    let plan_path = ceremony_dir.join("bootstrap-plan.json");
    dom_solana_daemon_route::owner_only::write(
        &plan_path,
        &serde_json::to_vec_pretty(&route.plan)
            .map_err(|error| format!("encode the plan: {error}"))?,
    )?;

    // Walk what the ceremony walks, before handing it anything. It reports one word for
    // nine different disagreements across seven files; this names the step.
    for (index, path) in plans.paths.iter().enumerate() {
        ceremony::verify_ceremony_inputs(path, &secrets[index], now_seconds)
            .map_err(|error| format!("party {index}: {error}"))?;
        // And that this plan names the participant ITS OWN authority derives. Both halves of
        // a mismatched pair are individually correct, so nothing above catches it.
        ceremony::verify_plan_names_its_own_identity(
            path,
            &route.identity_keys[index],
            route.registry.dom_genesis_hash,
            route.registry.dom_network_magic,
            route.identity_directions[index],
        )
        .map_err(|error| format!("party {index}: {error}"))?;
    }

    println!("state_dir={}", state_dir.display());
    println!("bootstrap_plan={}", plan_path.display());
    // Everything that later hands this route to the daemon must use the same second.
    println!("now_seconds={now_seconds}");
    // The shape of the route, so a later refusal can be compared against what was written
    // rather than against what was intended.
    println!("upstream_settlement={}", hex(&route.upstream.terms.settlement_id.0));
    println!("downstream_settlement={}", hex(&route.downstream.terms.settlement_id.0));
    println!("intent_shared={}", route.upstream.terms.intent_hash == route.downstream.terms.intent_hash);
    println!(
        "adaptor_point_shared={}",
        route.upstream.terms.adaptor_point_sec1 == route.downstream.terms.adaptor_point_sec1
    );
    println!("party_0={}", hex(&route.parties[0].0));
    println!("party_1={}", hex(&route.parties[1].0));
    for (index, path) in plans.paths.iter().enumerate() {
        println!("plan_{index}={}", path.display());
    }
    for (index, path) in secrets.iter().enumerate() {
        println!("secrets_{index}={}", path.display());
    }
    println!(
        "contracts_bootstrap={}",
        state_dir
            .join(dom_solana_daemon_route::SolanaRouteBootstrapPlanV1::contracts_bootstrap_relative())
            .display()
    );
    // The two pins the ceremony's report will carry, and which the manifest must then
    // declare. Printed as names so the next step does not have to know the layout.
    println!("route_id_hex={}", hex(&route.plan.route_id));
    Ok(())
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
