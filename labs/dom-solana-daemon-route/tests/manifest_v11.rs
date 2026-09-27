//! Milestone 0: the manifest this crate writes is the manifest the daemon reads.
//!
//! No artifact is signed yet, so nothing here claims the daemon would admit the
//! route -- authentication reads the artifacts and would refuse. What is
//! established is narrower and is the precondition for everything after it: the
//! bytes are the daemon's own canonical encoding of a V11 route carrying two
//! Solana positions, they decode back to an equivalent configuration, and the
//! create/reopen pair is a pair rather than two unrelated files.

use dom_interopd::{
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionChainFamilyV11,
    PRODUCTION_CREATE_CONFIG_FILE_V11, PRODUCTION_REOPEN_CONFIG_FILE_V11,
};
use dom_solana_daemon_route::SolanaRouteBootstrapPlanV1;

/// Stands in for a cluster genesis hash. Any nonzero value works here; the live
/// leg reads the real one from its harness.
/// The two clusters the route's two counterparty positions sit on. Different, because
/// the route-time policy refuses a pair that shares a chain id.
const UPSTREAM_CLUSTER: [u8; 32] = [0x7c; 32];
const DOWNSTREAM_CLUSTER: [u8; 32] = [0x8d; 32];

fn plan() -> SolanaRouteBootstrapPlanV1 {
    SolanaRouteBootstrapPlanV1::both_positions_on_solana(UPSTREAM_CLUSTER, DOWNSTREAM_CLUSTER)
}

#[test]
fn a_v11_route_with_two_solana_positions_encodes_and_decodes_unchanged() {
    for mode in [
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapModeV1::ReopenExisting,
    ] {
        let config = plan().config(mode).expect("the plan builds a V11 config");
        let bytes = config
            .canonical_bytes()
            .expect("the daemon's own encoder emits it");
        let decoded = ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(&bytes, mode)
            .expect("the daemon's own decoder accepts it");
        assert_eq!(
            decoded
                .canonical_bytes()
                .expect("the decoded config re-encodes"),
            bytes,
            "a decode/encode round trip changed the manifest"
        );
        let fields = decoded
            .universal_v11()
            .expect("the decoded config carries the universal V11 family");
        assert!(
            fields
                .legs
                .iter()
                .all(|leg| leg.family == ProductionChainFamilyV11::Sol),
            "a position of this route is not Solana"
        );
        assert_ne!(
            fields.legs[0].settlement_id, fields.legs[1].settlement_id,
            "the two positions are the same settlement"
        );
    }
}

#[test]
fn the_pins_are_declared_as_placeholders() {
    // Until the signed artifacts exist, a manifest from this crate is structurally
    // valid and would be refused at authentication. The type says so, so that a
    // later reader does not mistake a passing round trip for an admitted route.
    assert!(!plan().artifact_pins_are_complete());
}

#[test]
fn both_manifests_are_written_and_each_belongs_to_its_own_mode() {
    let directory = tempfile::tempdir().expect("a private working directory");
    let [create, reopen] = plan()
        .write_manifests(directory.path())
        .expect("both manifests are written");
    assert_eq!(
        create.file_name().and_then(|name| name.to_str()),
        Some(PRODUCTION_CREATE_CONFIG_FILE_V11)
    );
    assert_eq!(
        reopen.file_name().and_then(|name| name.to_str()),
        Some(PRODUCTION_REOPEN_CONFIG_FILE_V11)
    );

    let create_bytes = std::fs::read(&create).expect("the create manifest is readable");
    let reopen_bytes = std::fs::read(&reopen).expect("the reopen manifest is readable");
    assert_ne!(
        create_bytes, reopen_bytes,
        "the two manifests are byte-identical, so one of them carries the wrong mode"
    );

    // Each decodes in its own mode, and neither decodes in the other's: a loader
    // that accepted the create manifest as a reopen would reopen a route it was
    // asked to create.
    ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
        &create_bytes,
        ProductionBootstrapModeV1::Create,
    )
    .expect("the create manifest decodes as create");
    ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
        &reopen_bytes,
        ProductionBootstrapModeV1::ReopenExisting,
    )
    .expect("the reopen manifest decodes as reopen");
    assert!(
        ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
            &create_bytes,
            ProductionBootstrapModeV1::ReopenExisting,
        )
        .is_err(),
        "the create manifest decoded as a reopen"
    );
    assert!(
        ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
            &reopen_bytes,
            ProductionBootstrapModeV1::Create,
        )
        .is_err(),
        "the reopen manifest decoded as a create"
    );
}

/// Every role, and the path it is named for, stated independently of the lists the
/// crate holds.
///
/// This exists because two of those lists were transposed and nothing said so. The F6
/// V8 list had `AuthorityBundleV7` -- the only input file among the seven -- in the
/// first slot instead of the last, so the loader would have demanded an input file at
/// the claim-lineage path. The F6 V4 list had six leaves under other roles' names,
/// every one of them a managed file, so the daemon created whatever path the role
/// pointed at and an operator reading `upstream-observation` was looking at the
/// downstream binding log.
///
/// The accessors resolve a role through its own `ALL`, so a reordered list moves the
/// answer and this table catches it.
#[test]
fn the_layout_assigns_every_role_the_path_it_is_named_for() {
    use dom_interopd::{ProductionF6PathRoleV4 as V4, ProductionF6PathRoleV8 as V8};
    use dom_interopd::ProductionPathRoleV1 as R;
    use dom_solana_daemon_route::SolanaRouteBootstrapPlanV1 as P;

    for (role, expected) in [
        (R::RegistryStore, "artifacts/registry.v1.sqlite3"),
        (R::RegistryAuthorities, "artifacts/registry-authorities.v1"),
        (R::UpstreamTerms, "artifacts/upstream-terms.v1"),
        (R::DownstreamTerms, "artifacts/downstream-terms.v1"),
        (R::ParticipantBindings, "artifacts/participant-bindings.v1"),
        (R::RelayRoster, "artifacts/relay-roster.v1"),
        (R::TimePolicy, "artifacts/time-policy.v1"),
        (R::TimeEvidence, "artifacts/time-evidence.v1"),
        (R::DomWallet, "state/dom-wallet"),
        (R::RouteStore, "state/route.v1.sqlite3"),
        (R::TimeAnchorStore, "state/time-anchor.v1.sqlite3"),
        (R::CoordinatorStore, "state/coordinator.v1.sqlite3"),
        (R::DomActuatorStore, "state/dom-actuator.v1.sqlite3"),
        (R::EvmActuatorStore, "state/evm-actuator.v1.sqlite3"),
        (R::BitcoinActuatorStore, "state/bitcoin-actuator.v1.sqlite3"),
        (R::BitcoinParticipantState, "state/bitcoin-participant.v1.sqlite3"),
        (
            R::DomUpstreamParticipantState,
            "state/dom-upstream-participant.v1.sqlite3",
        ),
        (
            R::DomDownstreamParticipantState,
            "state/dom-downstream-participant.v1.sqlite3",
        ),
        (R::SolverInventoryStore, "state/solver-inventory.v1.sqlite3"),
        (R::RelayQueue, "state/relay/queue.v1"),
        (R::UpstreamRelaySender, "state/relay/upstream-sender.v1"),
        (R::UpstreamRelayInbox, "state/relay/upstream-inbox.v1"),
        (R::UpstreamRelayFrames, "state/relay/upstream-frames.v1"),
        (R::UpstreamContracts, "state/contracts/upstream.v1"),
        (R::DownstreamRelaySender, "state/relay/downstream-sender.v1"),
        (R::DownstreamRelayInbox, "state/relay/downstream-inbox.v1"),
        (R::DownstreamRelayFrames, "state/relay/downstream-frames.v1"),
        (R::DownstreamContracts, "state/contracts/downstream.v1"),
    ] {
        assert_eq!(P::relative(role), expected, "{role:?}");
    }

    for (role, expected) in [
        (V4::SolverStatusStore, "state/f6/solver-status.v1.sqlite3"),
        (
            V4::UpstreamPreF6TimeStore,
            "state/f6/upstream-pre-f6-time.v1.sqlite3",
        ),
        (
            V4::DownstreamPreF6TimeStore,
            "state/f6/downstream-pre-f6-time.v1.sqlite3",
        ),
        (
            V4::UpstreamBindingLog,
            "state/f6/upstream-binding-log.v1.sqlite3",
        ),
        (V4::UpstreamReceiptStore, "state/f6/upstream-receipts.v1.sqlite3"),
        (
            V4::UpstreamCandidateBook,
            "state/f6/upstream-candidate-book.v1.sqlite3",
        ),
        (
            V4::UpstreamCandidateAttestation,
            "state/f6/upstream-candidate-attestation.v1.sqlite3",
        ),
        (
            V4::DownstreamBindingLog,
            "state/f6/downstream-binding-log.v1.sqlite3",
        ),
        (
            V4::DownstreamReceiptStore,
            "state/f6/downstream-receipts.v1.sqlite3",
        ),
        (
            V4::DownstreamCandidateBook,
            "state/f6/downstream-candidate-book.v1.sqlite3",
        ),
        (
            V4::DownstreamCandidateAttestation,
            "state/f6/downstream-candidate-attestation.v1.sqlite3",
        ),
    ] {
        assert_eq!(P::f6_v4_relative(role), expected, "{role:?}");
    }

    for (role, expected) in [
        (V8::UpstreamStatusStore, "state/f6/v8-upstream-status.v1.sqlite3"),
        (
            V8::DownstreamStatusStore,
            "state/f6/v8-downstream-status.v1.sqlite3",
        ),
        (V8::UpstreamTimeStore, "state/f6/v8-upstream-time.v1.sqlite3"),
        (V8::DownstreamTimeStore, "state/f6/v8-downstream-time.v1.sqlite3"),
        (
            V8::UpstreamCandidateStore,
            "state/f6/v8-upstream-candidate.v1.sqlite3",
        ),
        (
            V8::DownstreamCandidateStore,
            "state/f6/v8-downstream-candidate.v1.sqlite3",
        ),
        // The only input file among the seven, and the last role.
        (V8::AuthorityBundleV7, "artifacts/f6/authority-bundle.v8"),
    ] {
        assert_eq!(P::f6_v8_relative(role), expected, "{role:?}");
    }

    // The per-position paths are in the list too, because the loader validates their
    // parent chains like any other: leaving them out is what left `state/upstream` and
    // `state/downstream` uncreated and had the loader refuse the whole directory.
    for expected in [
        "state/upstream/solana-actuator.v1.sqlite3",
        "state/downstream/solana-actuator.v1.sqlite3",
        "artifacts/upstream-solana-authority-bundle.v1",
        "artifacts/downstream-solana-authority-bundle.v1",
    ] {
        assert!(
            P::path_relatives().contains(&expected),
            "{expected} is validated by the loader and is not in the layout's path list"
        );
    }

    // Fifty paths, all distinct: two roles sharing a path would make one of them
    // silently adopt the other's state.
    let all = P::path_relatives();
    let distinct: std::collections::BTreeSet<&str> = all.iter().copied().collect();
    assert_eq!(distinct.len(), all.len(), "two roles share a path");
}
