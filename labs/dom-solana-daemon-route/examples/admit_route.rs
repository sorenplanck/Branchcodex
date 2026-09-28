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
use dom_solana_daemon_route::{declared_inputs, SolanaRouteBootstrapPlanV1 as Plan};
use route_executor::LegIdV1;

fn main() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let ([state_dir, plan_json, now_seconds, commit_hex, reveal_hex], run_inputs) =
        match arguments.as_slice() {
            [a, b, c, d, e] => ([a, b, c, d, e], None),
            // The two extra arguments turn admission into admission PLUS the inputs a run
            // needs: one Solana RPC endpoint the daemon should talk to, and a directory to
            // leave them in. Admission itself is unchanged, so the proof above still stands
            // on its own when they are absent.
            [a, b, c, d, e, endpoint, out_dir] => {
                ([a, b, c, d, e], Some((endpoint.clone(), PathBuf::from(out_dir))))
            }
            _ => {
                return Err("usage: admit_route <state-dir> <plan-json> <now-seconds> \
                            <commit-hex> <reveal-hex> [<solana-rpc-endpoint> <run-inputs-dir>]"
                    .to_owned())
            }
        };
    // The same second the route was provisioned around. The registry's validity window, the
    // time policy's window and both schedules are all relative to it, so a different one
    // here would authenticate a route against a clock it was not built for.
    let now_seconds: u64 = now_seconds
        .parse()
        .map_err(|error| format!("the trusted second: {error}"))?;
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
    let inputs = load_authenticated_production_inputs_v1(&bootstrap, now_seconds)
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

    if let Some((endpoint, out_dir)) = run_inputs {
        // Everything below is public: the two digests `production-route-services.v8.json`
        // must carry are the ones the daemon recomputes from this same admission, and both
        // accessors that produce them are part of `dom-interopd`'s public surface. Nothing
        // here is a second opinion about the route -- it is the route, restated in the one
        // document the run reads.
        let route_services = route_services_document(&inputs, &endpoint)?;
        dom_solana_daemon_route::owner_only::directory(&out_dir)?;
        dom_solana_daemon_route::owner_only::write(
            &out_dir.join("route-services.json"),
            route_services.as_bytes(),
        )?;
        println!("route_services={}", out_dir.join("route-services.json").display());

        // The sidecar a run binds before any settlement work. This party LISTENS on both
        // links; its counterparty connects to the same two addresses. The mode is the sole
        // authority for the Noise role, so stating the operation is how the role is chosen.
        use dom_interopd::ProductionRelayEndpointModeV1 as Mode;
        declared_inputs::write_relay_network_config(
            &state_dir,
            (Mode::Listen, "127.0.0.1:9101".parse().map_err(|error| {
                format!("the upstream relay address: {error}")
            })?),
            (Mode::Listen, "127.0.0.1:9102".parse().map_err(|error| {
                format!("the downstream relay address: {error}")
            })?),
        )?;
        println!("relay_network=listen:9101,9102");
    }
    Ok(())
}

/// The `prepare-route-services-v11` document, built from the admitted route.
///
/// `chain_id` is the COUNTERPARTY leg's, not the DOM leg's: this document names the service
/// the daemon must reach for that position's own chain, and for both positions of this route
/// that chain is Solana.
fn route_services_document(
    inputs: &dom_interopd::AuthenticatedProductionInputsV1,
    endpoint: &str,
) -> Result<String, String> {
    let leg = |terms: &kaystra_core::terms::SettlementTermsV1| {
        serde_json::json!({
            "settlement_id": terms.settlement_id.0,
            "chain_id": terms.counterparty_leg.chain_id.0,
            "service": {
                "family": "SOL",
                "endpoints": [endpoint],
                // One endpoint is one vote. A quorum above the number of endpoints would be
                // unreachable by construction, and the daemon refuses it rather than
                // silently settling for fewer confirmations than it was told to require.
                "quorum": 1,
            },
        })
    };
    serde_json::to_string_pretty(&serde_json::json!({
        "version": 8,
        "route_id": inputs.admission().route_id(),
        "composition_digest": inputs.composition().binding_digest(),
        "registry_digest": inputs.admission().registry_digest(),
        "legs": [
            leg(inputs.composition().upstream()),
            leg(inputs.composition().downstream()),
        ],
    }))
    .map_err(|error| format!("encode the route services document: {error}"))
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
