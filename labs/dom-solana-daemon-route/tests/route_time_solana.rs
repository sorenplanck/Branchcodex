//! The route's time authority: the signed policy and the signed evidence, and the four
//! pins they determine.
//!
//! What these tests establish is that the policy on disk is the policy the daemon will
//! rebuild. The daemon does not take the artifact's word: it decodes the file,
//! reconstructs the policy from the authenticated registry and the two frozen terms
//! with `RouteTimePolicyV2::from_registry`, and refuses unless the two are equal. So
//! the decisive assertion here is that same reconstruction, run against the artifact.
//!
//! This is also where the Solana clock kind is exercised end to end. `counterparty_binding`
//! admits a Solana counterparty only when the chain kind, the deployment, the deadline
//! shape and the lock mechanism all line up -- `ChainKindV1::Solana`,
//! `ChainDeploymentV1::Solana`, `TimelockSpec::TimestampSeconds` and
//! `LockMechanism::CrossCurveConditionLock` -- and it then stamps the checkpoint with
//! `ClockKindV2::Solana`. A policy that builds at all is proof those four agree.

mod common;

use common::{provision_all, TIME_EVIDENCE, TIME_POLICY};
use dom_solana_daemon_route::SolanaRouteBootstrapPlanV1;
use route_time_anchor::{
    CheckpointRoleV2, ClockKindV2, RouteTimeEvidenceV2, RouteTimePolicyV2, SignedRouteTimeEvidenceV2,
    SignedRouteTimePolicyV2,
};

fn decoded_policy(provisioned: &common::Provisioned) -> RouteTimePolicyV2 {
    let bytes = std::fs::read(provisioned.directory.path().join(TIME_POLICY))
        .expect("the policy artifact was written");
    let signed = SignedRouteTimePolicyV2::decode(&bytes).expect("the signed policy decodes");
    RouteTimePolicyV2::decode(signed.policy_bytes()).expect("the policy decodes")
}

fn decoded_evidence(provisioned: &common::Provisioned) -> RouteTimeEvidenceV2 {
    let bytes = std::fs::read(provisioned.directory.path().join(TIME_EVIDENCE))
        .expect("the evidence artifact was written");
    let signed = SignedRouteTimeEvidenceV2::decode(&bytes).expect("the signed evidence decodes");
    RouteTimeEvidenceV2::decode(signed.evidence_bytes()).expect("the evidence decodes")
}

#[test]
fn both_artifacts_decode_and_hash_to_the_pins_they_declare() {
    let provisioned = provision_all();
    let pins = provisioned
        .plan
        .route_time
        .expect("the plan carries the provisioned time artifacts");

    assert_eq!(
        decoded_policy(&provisioned)
            .policy_digest()
            .expect("the policy digests"),
        pins.time_policy_digest
    );
    assert_eq!(
        decoded_evidence(&provisioned)
            .evidence_digest()
            .expect("the evidence digests"),
        pins.time_evidence_digest
    );
    assert_ne!(pins.time_policy_authority_set_digest, [0; 32]);
    assert_ne!(pins.time_evidence_authority_set_digest, [0; 32]);
    // Three independent authorities, and the bundle refuses two that are equal. The
    // pins are how the bootstrap says which is which.
    assert_ne!(
        pins.time_policy_authority_set_digest,
        pins.time_evidence_authority_set_digest
    );
}

/// The reconstruction the daemon performs before it will accept the policy.
#[test]
fn the_policy_on_disk_is_the_policy_the_registry_and_the_terms_reconstruct() {
    let provisioned = provision_all();
    let registry = provisioned.resolved_registry();
    let rebuilt = RouteTimePolicyV2::from_registry(
        &registry,
        &provisioned.upstream,
        &provisioned.downstream,
        decoded_policy(&provisioned).limits(),
    )
    .expect("the policy reconstructs from the registry and both terms");
    assert_eq!(
        rebuilt,
        decoded_policy(&provisioned),
        "the daemon rebuilds the policy from the registry and refuses anything else"
    );
}

#[test]
fn the_three_checkpoints_are_the_hub_and_the_two_solana_clusters() {
    let provisioned = provision_all();
    let policy = decoded_policy(&provisioned);
    let bindings = policy.checkpoint_bindings();

    assert_eq!(bindings[0].role(), CheckpointRoleV2::Hub);
    assert_eq!(bindings[0].clock_kind(), ClockKindV2::DomHeight);
    assert_eq!(bindings[0].chain_id().0, provisioned.dom_chain_id);

    assert_eq!(bindings[1].role(), CheckpointRoleV2::UpstreamCounterparty);
    assert_eq!(bindings[2].role(), CheckpointRoleV2::DownstreamCounterparty);
    for binding in &bindings[1..] {
        // The clock kind is stamped by `counterparty_binding`, and it reaches
        // `ClockKindV2::Solana` only when the chain kind, the deployment, a timestamp
        // deadline and the cross-curve condition lock all agree.
        assert_eq!(binding.clock_kind(), ClockKindV2::Solana);
    }
    assert_eq!(
        bindings[1].chain_id().0,
        provisioned.upstream_facts.genesis_hash
    );
    assert_eq!(
        bindings[2].chain_id().0,
        provisioned.downstream_facts.genesis_hash
    );
    assert_ne!(bindings[1].chain_id(), bindings[2].chain_id());
}

#[test]
fn the_evidence_covers_the_policy_and_every_checkpoint_it_binds() {
    let provisioned = provision_all();
    let policy = decoded_policy(&provisioned);
    let evidence = decoded_evidence(&provisioned);

    assert_eq!(
        evidence.policy_digest(),
        policy.policy_digest().expect("the policy digests"),
        "evidence that does not name its policy revalidates nothing"
    );
    assert_eq!(evidence.route_scope_digest(), policy.route_scope_digest());
    assert!(evidence.sequence() > 0, "a zero sequence is refused");
    assert!(evidence.observed_at_seconds() < evidence.expires_at_seconds());
    // Each checkpoint copies its identity from the policy binding, so a checkpoint that
    // named another chain would not be evidence about this route.
    for (checkpoint, binding) in evidence
        .checkpoints()
        .iter()
        .zip(policy.checkpoint_bindings())
    {
        assert_eq!(checkpoint.role, binding.role());
        assert_eq!(checkpoint.chain_id, binding.chain_id());
        assert_eq!(checkpoint.profile_digest, binding.profile_digest());
        assert!(checkpoint.canonical_tip_height >= checkpoint.anchor_height);
    }
}

#[test]
fn the_time_artifacts_turn_four_more_pins_into_measurements() {
    let provisioned = provision_all();
    let before = SolanaRouteBootstrapPlanV1::both_positions_on_solana(
        provisioned.upstream_facts.genesis_hash,
        provisioned.downstream_facts.genesis_hash,
    )
    .with_registry(provisioned.registry)
    .with_terms(provisioned.plan.terms.expect("the provisioned terms"))
    .with_roster(provisioned.plan.roster.expect("the provisioned roster"))
    .with_participants(provisioned.plan.participants.expect("the bindings"));
    assert_eq!(before.measured_pin_count(), 9);

    let after = before.with_route_time(provisioned.plan.route_time.expect("the time artifacts"));
    assert_eq!(
        after.measured_pin_count(),
        13,
        "two authority-set digests, the policy digest and the evidence digest"
    );
    // Every pin that is the digest of an artifact is now a measurement. The six that
    // remain are identities a deployment declares, not files this crate can write.
    assert!(
        after.artifact_pins_are_complete(),
        "thirteen artifact pins measured is the whole artifact side of the bootstrap"
    );
}

/// The whole bootstrap on disk: every artifact written, every artifact pin measured,
/// the six identities declared, and both manifests encoded from that plan.
///
/// This is as far as this crate can assert on its own. What it does NOT assert is that
/// `load_production_bootstrap_v11` and `load_authenticated_production_inputs_v1` accept
/// the directory -- that needs the rest of the layout the daemon creates, and it is the
/// next step rather than something to imply here.
#[test]
fn the_complete_artifact_side_encodes_both_manifests() {
    let provisioned = provision_all();
    // The fixture declares the identities before the artifacts that bind the route id.
    let plan = provisioned.plan;

    assert!(plan.artifact_pins_are_complete());
    assert_eq!(plan.route_id, [0x31; 32], "declaring identities sets the route id");

    // Written into the same state directory the artifacts are in, which is what the
    // daemon is handed.
    let written = plan
        .write_manifests(provisioned.directory.path())
        .expect("both manifests encode from a plan with every artifact pin measured");
    assert_eq!(written.len(), 2);
    for path in written {
        assert!(path.exists(), "{} was not written", path.display());
    }

    // Every artifact the bootstrap names is beside them.
    for relative in [
        "artifacts/registry.v1.sqlite3",
        "artifacts/registry-authorities.v1",
        common::UPSTREAM_TERMS,
        common::DOWNSTREAM_TERMS,
        common::RELAY_ROSTER,
        common::PARTICIPANT_BINDINGS,
        TIME_POLICY,
        TIME_EVIDENCE,
    ] {
        assert!(
            provisioned.directory.path().join(relative).exists(),
            "{relative} is named by a pin and is not on disk"
        );
    }
}
