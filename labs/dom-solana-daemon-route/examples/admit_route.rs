//! Finish a provisioned route with the ceremony's output, and ask the daemon to admit it.
//!
//! This is the second half of a flow the ceremony splits in two. The first half provisions
//! the route and emits the ceremony's plans; the ceremony then runs between the two parties
//! and produces the Contracts bootstrap artifact and its two stage digests. This half takes
//! those three things, declares the remaining inputs, writes the manifests and hands the
//! directory to `load_production_bootstrap_v11` and
//! `load_authenticated_production_inputs_v1`.
//!
//! # Why the plan is read from a file rather than rebuilt
//!
//! Provisioning generates a fresh condition scalar, so rebuilding the route would freeze
//! DIFFERENT terms with different digests. The pins cannot be recomputed after the ceremony;
//! they have to be carried. The first half writes the plan and this half reads it.
//!
//! Usage:
//!
//! ```text
//! admit_route <state-dir> <plan-json> <commit-hex> <reveal-hex>
//! ```

use std::path::PathBuf;

use dom_interopd::{
    load_authenticated_production_inputs_v1, load_production_bootstrap_v11,
    ProductionBootstrapModeV1, ProductionF6PathRoleV8, ProductionPathRoleV1,
};
use dom_solana_daemon_route::{declared_inputs, laboratory, SolanaRouteBootstrapPlanV1 as Plan};
use route_executor::LegIdV1;

fn main() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [state_dir, plan_json, commit_hex, reveal_hex] = arguments.as_slice() else {
        return Err(
            "usage: admit_route <state-dir> <plan-json> <commit-hex> <reveal-hex>".to_owned(),
        );
    };
    let state_dir = PathBuf::from(state_dir)
        .canonicalize()
        .map_err(|error| format!("canonicalize the state directory: {error}"))?;
    let plan: Plan = serde_json::from_slice(
        &std::fs::read(plan_json).map_err(|error| format!("read the plan: {error}"))?,
    )
    .map_err(|error| format!("decode the plan: {error}"))?;

    // Every parent chain the loader walks, including the parents of the managed paths it
    // then requires to be absent.
    declared_inputs::create_parent_directories(&state_dir, &Plan::path_relatives())?;

    // The inputs the layout requires that carry no pin: the wallet the chain signers open
    // later with a passphrase this program must never hold, and the two per-position
    // authority bundles, whose digests the manifest declares.
    declared_inputs::write_dom_wallet(
        &state_dir,
        Plan::relative(ProductionPathRoleV1::DomWallet),
        b"a wallet this program did not create",
    )?;
    let upstream_bundle = declared_inputs::write_leg_authority_bundle(
        &state_dir,
        Plan::upstream_leg_authority_bundle_relative(),
        b"the upstream position's authority material",
    )?;
    let downstream_bundle = declared_inputs::write_leg_authority_bundle(
        &state_dir,
        Plan::downstream_leg_authority_bundle_relative(),
        b"the downstream position's authority material",
    )?;
    let f6 = declared_inputs::write_f6_authority_bundle(
        &state_dir,
        Plan::f6_v8_relative(ProductionF6PathRoleV8::AuthorityBundleV7),
        b"an F6 authority bundle this program did not build",
    )?;

    let plan = plan
        .with_f6_authority_bundle(f6)
        .with_leg_authority_bundles(upstream_bundle, downstream_bundle)
        .with_contracts_bootstrap(hex32(commit_hex)?, hex32(reveal_hex)?);
    if !plan.artifact_pins_are_complete() {
        return Err("the plan is missing artifact pins the route needs".to_owned());
    }
    plan.write_manifests(&state_dir)
        .map_err(|error| format!("write the manifests: {error:?}"))?;

    let bootstrap = load_production_bootstrap_v11(&state_dir, ProductionBootstrapModeV1::Create)
        .map_err(|error| format!("the daemon refused the directory: {error:?}"))?;
    let inputs = load_authenticated_production_inputs_v1(&bootstrap, laboratory::NOW_SECONDS)
        .map_err(|error| format!("the daemon refused to admit the route: {error:?}"))?;

    // The mission, stated as two questions the daemon answers: can it start an operation
    // that begins on Solana, and can it finish one that ends on Solana.
    for (leg, name) in [
        (LegIdV1::Upstream, "upstream"),
        (LegIdV1::Downstream, "downstream"),
    ] {
        let session = inputs
            .solana_session(leg)
            .ok_or_else(|| format!("the {name} position has no authenticated Solana session"))?;
        println!(
            "{name}_solana_session=authenticated terms_digest={}",
            hex(&session.terms_digest())
        );
    }
    println!("route_id={}", hex(&inputs.admission().route_id()));
    println!("admitted=true");
    Ok(())
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err(format!("a stage digest is 64 hex characters, not {}", text.len()));
    }
    let mut out = [0u8; 32];
    for (slot, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| "not ascii".to_owned())?;
        out[slot] = u8::from_str_radix(pair, 16).map_err(|error| format!("{pair}: {error}"))?;
    }
    Ok(out)
}
