//! The daemon reading the directory this crate provisions.
//!
//! Everything before this file asserts one artifact at a time against the rule that
//! governs it. This one hands the whole directory to `load_production_bootstrap_v11`
//! and then to `load_authenticated_production_inputs_v1`, which is the only way to find
//! out whether the parts agree.
//!
//! # What stops it, and why that is the protocol rather than a gap
//!
//! The load reaches the Contracts bootstrap artifact and refuses, because that artifact
//! is the output of a ceremony BETWEEN THE TWO PARTICIPANTS and not something a route
//! provisioner writes. The daemon ships the driver: `bootstrap_command_v13`, "advance
//! only the bootstrap ceremony using public files and a bounded private stdin; repeat
//! with the same plan/custody after copying the missing peer files". Both the producer
//! and `authenticate_contracts_bootstrap_v1` are `pub(crate)`, so this crate could not
//! build one; and it should not, because driving both custodies from one process would
//! collapse a two-party protocol into one party holding everything.
//!
//! So the test asserts how far the daemon got, and it asserts it by evidence rather
//! than by the error alone: the route store and the time-anchor store exist afterwards.
//! The loader creates those while authenticating, BEFORE it authenticates the Contracts
//! bootstrap, so their presence means the layout, the manifests, the registry, both
//! frozen terms, the ordered route scope, the relay roster, the signed time policy and
//! the signed evidence were all accepted.

mod common;

use common::{provision_all, NOW_SECONDS};
use dom_interopd::{
    load_authenticated_production_inputs_v1, load_production_bootstrap_v11,
    ProductionBootstrapModeV1, ProductionPathRoleV1,
};
use dom_solana_daemon_route::{
    declared_inputs, RouteIdentitiesV1, SolanaRouteBootstrapPlanV1 as Plan,
};

fn identities() -> RouteIdentitiesV1 {
    RouteIdentitiesV1 {
        route_id: [0x31; 32],
        process_owner_id: [0x32; 32],
        coordinator_id: [0x33; 32],
        coordinator_plan_authority_id: [0x34; 32],
        actuator_bindings_digest: [0x35; 32],
        solver_inventory_binding_digest: [0x36; 32],
    }
}

/// Provision every input the layout requires, then write both manifests.
fn prepared() -> (tempfile::TempDir, std::path::PathBuf) {
    let provisioned = provision_all();
    // Canonical, because `validate_state_dir` refuses a state directory whose
    // `canonicalize` differs from itself -- a symlink anywhere above it is fatal, and a
    // temporary directory is reached through whatever `TMPDIR` happens to be.
    let root = provisioned
        .directory
        .path()
        .canonicalize()
        .expect("a canonical state directory");

    // Parents first: `validate_parent_chain` walks from the state directory down to
    // every path and requires each directory on the way to exist and be owner-only --
    // including the parents of the managed paths it then demands be absent.
    // This also verifies its own post-condition and names the path that fails, because
    // the daemon refuses all four conditions the same way and mentions none of them.
    declared_inputs::create_parent_directories(&root, &Plan::path_relatives())
        .expect("every parent directory of every path in the layout");
    declared_inputs::create_contracts_transport_identity(
        &root,
        Plan::contracts_transport_identity_relative(),
    )
    .expect("the transport identity authority directory");

    declared_inputs::write_dom_wallet(
        &root,
        Plan::relative(ProductionPathRoleV1::DomWallet),
        // The layout wants a non-empty owner-only file and nothing more: the wallet is
        // opened later by the chain signers, with a passphrase this crate never holds.
        b"a wallet this crate did not create",
    )
    .expect("the DOM wallet input");
    declared_inputs::write_contracts_budget_policy(
        &root,
        Plan::contracts_budget_policy_relative(),
        b"a budget policy this deployment decided",
    )
    .expect("the budget policy input");
    declared_inputs::place_contracts_bootstrap(
        &root,
        Plan::contracts_bootstrap_relative(),
        // Correct length, unauthenticated content. The length matters: a wrong one is
        // refused before the loader reads anything else, and then this test would prove
        // nothing about the rest.
        &vec![0x5c; declared_inputs::CONTRACTS_BOOTSTRAP_BYTES],
    )
    .expect("the Contracts bootstrap artifact");

    let f6 = declared_inputs::write_f6_authority_bundle(
        &root,
        Plan::f6_v8_relative(dom_interopd::ProductionF6PathRoleV8::AuthorityBundleV7),
        b"an F6 authority bundle this crate did not build",
    )
    .expect("the F6 authority bundle");

    // Re-verified after every writer has run: creating the contracts identity directory
    // and the artifact files must not have left any chain invalid.
    declared_inputs::verify_parent_chains(&root, &Plan::path_relatives())
        .expect("every parent chain still valid after the inputs were written");

    let plan = provisioned
        .plan
        .with_identities(identities())
        .with_f6_authority_bundle(f6);
    assert!(plan.artifact_pins_are_complete());
    assert!(plan.f6_authority_bundle_is_measured());
    plan.write_manifests(&root).expect("both manifests");

    (provisioned.directory, root)
}

/// Every entry under the root, with its mode and owner.
///
/// `InvalidStateAuthority` covers four conditions across the state directory and every
/// parent chain and names none of them. The crate's own verification replicates all four
/// and passes, so when the daemon still refuses, the only thing left to do is look at
/// what is actually on disk -- and looking is cheaper than another round of reasoning.
fn tree(root: &std::path::Path) -> String {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    fn walk(path: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        let mut sorted: Vec<_> = entries.filter_map(Result::ok).collect();
        sorted.sort_by_key(std::fs::DirEntry::path);
        for entry in sorted {
            let entry_path = entry.path();
            let Ok(metadata) = std::fs::symlink_metadata(&entry_path) else {
                continue;
            };
            out.push(format!(
                "  {:04o} uid={} {}{}",
                metadata.permissions().mode() & 0o7777,
                metadata.uid(),
                entry_path
                    .strip_prefix(root)
                    .unwrap_or(&entry_path)
                    .display(),
                if metadata.is_dir() { "/" } else { "" }
            ));
            if metadata.is_dir() {
                walk(&entry_path, root, out);
            }
        }
    }
    let mut out = Vec::new();
    let metadata = std::fs::symlink_metadata(root).expect("the root");
    out.push(format!(
        "  {:04o} uid={} . (root {})",
        metadata.permissions().mode() & 0o7777,
        metadata.uid(),
        root.display()
    ));
    walk(root, root, &mut out);
    out.join("\n")
}

/// The milestone: the daemon validates the whole directory.
#[test]
fn the_daemon_accepts_the_layout_this_crate_provisions() {
    let (_directory, root) = prepared();
    let bootstrap = load_production_bootstrap_v11(&root, ProductionBootstrapModeV1::Create)
        .unwrap_or_else(|error| {
            panic!(
                "the daemon refused the state directory, the manifests or the layout:                  {error:?}\n{}",
                tree(&root)
            )
        });

    // Resolved against the daemon's own layout rather than against this crate's list:
    // role and path agree after a real load, not only in a table.
    for role in ProductionPathRoleV1::ALL {
        assert_eq!(
            bootstrap.layout().path(role),
            root.join(Plan::relative(role)).as_path(),
            "{role:?}"
        );
    }
}

/// How far authentication gets, asserted by what the loader left on disk.
#[test]
fn authentication_reaches_the_two_party_ceremony_and_stops_there() {
    let (_directory, root) = prepared();
    let bootstrap = load_production_bootstrap_v11(&root, ProductionBootstrapModeV1::Create)
        .unwrap_or_else(|error| panic!("the validated bootstrap: {error:?}\n{}", tree(&root)));

    let refusal = load_authenticated_production_inputs_v1(&bootstrap, NOW_SECONDS)
        .err()
        .expect("a Contracts bootstrap this crate did not produce cannot authenticate");

    // The route store and the time-anchor store are created while authenticating and
    // before the Contracts bootstrap is authenticated. Their presence is the evidence
    // that everything this crate provisions was accepted first.
    for relative in [
        Plan::relative(ProductionPathRoleV1::RouteStore),
        Plan::relative(ProductionPathRoleV1::TimeAnchorStore),
    ] {
        assert!(
            root.join(relative).exists(),
            "{relative} was not created, so authentication stopped before the route was \
             admitted and the refusal below is about something earlier: {refusal:?}"
        );
    }
}
