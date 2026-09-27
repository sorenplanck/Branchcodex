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

use common::{identities, provision_all, NOW_SECONDS};
use dom_interopd::{
    load_authenticated_production_inputs_v1, load_production_bootstrap_v11,
    ProductionBootstrapModeV1, ProductionPathRoleV1,
};
use dom_solana_daemon_route::{declared_inputs, SolanaRouteBootstrapPlanV1 as Plan};

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
        // A laboratory passphrase, stated as one. The ceremony reopens the authority with
        // it, and a deployment's belongs to whoever holds the identity.
        b"a laboratory contracts identity passphrase",
    )
    .expect("the transport identity authority");

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

    // One per position, and the loader reads both after the layout: a route whose
    // positions carry no authority bundle is refused there, not at the layout.
    let upstream_bundle = declared_inputs::write_leg_authority_bundle(
        &root,
        Plan::upstream_leg_authority_bundle_relative(),
        b"the upstream position's authority material",
    )
    .expect("the upstream leg authority bundle");
    let downstream_bundle = declared_inputs::write_leg_authority_bundle(
        &root,
        Plan::downstream_leg_authority_bundle_relative(),
        b"the downstream position's authority material",
    )
    .expect("the downstream leg authority bundle");

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

    // The fixture already declared the identities, before the artifacts that bind the
    // route id. Re-declaring them here would be harmless only by coincidence.
    let plan = provisioned
        .plan
        .with_f6_authority_bundle(f6)
        .with_leg_authority_bundles(upstream_bundle, downstream_bundle);
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

/// Load a directory built up to one stage, and report what the daemon said.
///
/// `InvalidStateAuthority` names none of the four conditions it covers, and this crate's
/// own verification of all four passes on every path -- the tree dump shows every
/// directory at 0700 and every file at 0600, all owned by the running uid. So the useful
/// question is no longer "which condition" but "which addition", and that is answered by
/// building the directory in stages and loading after each one.
fn staged_report() -> String {
    let mut lines = Vec::new();
    for stage in 0..5 {
        let directory = tempfile::tempdir().expect("a working directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("a canonical directory");
        let mut plan =
            Plan::both_positions_on_solana([0x7c; 32], [0x8d; 32]).with_identities(identities());

        if stage >= 1 {
            declared_inputs::create_parent_directories(&root, &Plan::path_relatives())
                .expect("parents");
        }
        if stage >= 2 {
            declared_inputs::create_contracts_transport_identity(
                &root,
                Plan::contracts_transport_identity_relative(),
                b"a laboratory contracts identity passphrase",
            )
            .expect("identity directory");
        }
        if stage >= 3 {
            for relative in [
                Plan::relative(ProductionPathRoleV1::DomWallet),
                Plan::contracts_budget_policy_relative(),
            ] {
                declared_inputs::write_dom_wallet(&root, relative, &[0x11; 8])
                    .expect("an input file");
            }
        }
        // Stage four adds every remaining declared input as filler, so the layout loop
        // gets past every InputFile role and reaches the managed ones. If four is
        // accepted and the full directory is not, the difference is what provision_all
        // writes and nothing else.
        if stage >= 4 {
            declared_inputs::place_contracts_bootstrap(
                &root,
                Plan::contracts_bootstrap_relative(),
                &vec![0x5c; declared_inputs::CONTRACTS_BOOTSTRAP_BYTES],
            )
            .expect("the Contracts bootstrap");
            declared_inputs::write_f6_authority_bundle(
                &root,
                Plan::f6_v8_relative(dom_interopd::ProductionF6PathRoleV8::AuthorityBundleV7),
                b"filler",
            )
            .expect("the F6 bundle");
            let upstream = declared_inputs::write_leg_authority_bundle(
                &root,
                Plan::upstream_leg_authority_bundle_relative(),
                b"filler",
            )
            .expect("the upstream leg bundle");
            let downstream = declared_inputs::write_leg_authority_bundle(
                &root,
                Plan::downstream_leg_authority_bundle_relative(),
                b"filler too",
            )
            .expect("the downstream leg bundle");
            plan = plan.with_leg_authority_bundles(upstream, downstream);
            for role in [
                ProductionPathRoleV1::RegistryStore,
                ProductionPathRoleV1::RegistryAuthorities,
                ProductionPathRoleV1::UpstreamTerms,
                ProductionPathRoleV1::DownstreamTerms,
                ProductionPathRoleV1::ParticipantBindings,
                ProductionPathRoleV1::RelayRoster,
                ProductionPathRoleV1::TimePolicy,
                ProductionPathRoleV1::TimeEvidence,
            ] {
                declared_inputs::write_dom_wallet(&root, Plan::relative(role), b"filler")
                    .expect("an input file");
            }
        }
        // The manifests last: the loader reads them before the layout, and a missing one
        // is a different error entirely.
        plan.write_manifests(&root).expect("manifests");

        let outcome =
            match load_production_bootstrap_v11(&root, ProductionBootstrapModeV1::Create) {
                Ok(_) => "accepted".to_owned(),
                Err(error) => format!("{error:?}"),
            };
        lines.push(format!("  stage {stage}: {outcome}"));
    }
    lines.join("\n")
}

/// The milestone: the daemon validates the whole directory.
#[test]
fn the_daemon_accepts_the_layout_this_crate_provisions() {
    let (_directory, root) = prepared();
    let bootstrap = load_production_bootstrap_v11(&root, ProductionBootstrapModeV1::Create)
        .unwrap_or_else(|error| {
            panic!(
                "the daemon refused the state directory, the manifests or the layout: {error:?}\n{}\nstaged, on fresh directories:\n{}",
                tree(&root),
                staged_report()
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

    // The time-anchor store is the marker, and the route store is NOT.
    //
    // Reading the loader's order settles which: it creates the time-anchor store, installs
    // the signed policy, installs the signed evidence and proves the route ladder, and only
    // THEN authenticates the Contracts bootstrap. The route store is created after both
    // that and the participant bundle, so it cannot exist while the ceremony artifact is
    // unauthenticated -- asserting on it would fail for the very reason the test expects.
    //
    // So the time-anchor store's presence is the evidence: the layout, both manifests, the
    // registry, both frozen terms, the ordered route scope, the relay roster, the signed
    // time policy, the signed evidence and the ladder they imply were all accepted.
    let marker = Plan::relative(ProductionPathRoleV1::TimeAnchorStore);
    assert!(
        root.join(marker).exists(),
        "{marker} was not created, so authentication stopped before the time authority was \
         established and the refusal is about something earlier: {refusal:?}"
    );
    assert!(
        !root
            .join(Plan::relative(ProductionPathRoleV1::RouteStore))
            .exists(),
        "the route store is created only after the Contracts bootstrap authenticates, so \
         its presence would mean the ceremony artifact was accepted: {refusal:?}"
    );
}
