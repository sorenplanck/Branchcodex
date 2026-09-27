//! The participant bindings artifact, and the one pin it determines.
//!
//! A Solana position carries no participant signature. `dom-interopd` states the
//! reason where the type is defined: the authentication anchor is the cross-curve
//! DLEQ inside the binding, which `solana_profile::validate_setup` verifies against
//! the frozen terms. So this artifact is the two bindings the leg produced when it
//! established each position, and what these tests establish is that the file on disk
//! is exactly that -- not a plausible encoding of something similar.
//!
//! `ProductionSolanaLegSetupV1` exposes no accessors, by the same design as its
//! Monero counterpart: the bundle is written and decoded by the daemon, never
//! inspected field by field by a caller. So the decisive assertion here is structural
//! equality -- the bundle decoded from the file equals a bundle built independently
//! from the two established positions -- and the field-level checks the daemon makes
//! are asserted against those positions, which do expose the profile and the binding.

mod common;

use common::{provision_all, PARTICIPANT_BINDINGS};
use dom_interopd::{
    ProductionParticipantBindingBundleV1, ProductionRoutePositionV1, ProductionSolanaLegSetupV1,
};

#[test]
fn the_artifact_decodes_and_hashes_to_the_pin_it_declares() {
    let provisioned = provision_all();
    let pin = provisioned
        .plan
        .participants
        .expect("the plan carries the provisioned bindings");
    let bytes = std::fs::read(provisioned.directory.path().join(PARTICIPANT_BINDINGS))
        .expect("the participant bindings artifact was written");
    let decoded = ProductionParticipantBindingBundleV1::decode_canonical(&bytes)
        .expect("the artifact decodes strictly");

    assert_eq!(
        decoded.canonical_bytes().expect("a valid bundle encodes"),
        bytes,
        "the artifact is not the canonical encoding of what it decodes to"
    );
    assert_eq!(
        decoded.bundle_digest().expect("the bundle digests"),
        pin.participant_bindings_digest
    );
    assert_eq!(decoded.route_id(), provisioned.plan.route_id);
}

#[test]
fn the_decoded_bundle_is_the_two_positions_that_were_established() {
    let provisioned = provision_all();
    let bytes = std::fs::read(provisioned.directory.path().join(PARTICIPANT_BINDINGS))
        .expect("the artifact was written");
    let decoded = ProductionParticipantBindingBundleV1::decode_canonical(&bytes)
        .expect("the artifact decodes");

    let rebuilt = ProductionParticipantBindingBundleV1::new_with_counterparty_bindings(
        provisioned.plan.route_id,
        Vec::new(),
        Vec::new(),
        vec![
            ProductionSolanaLegSetupV1::new(
                ProductionRoutePositionV1::Upstream,
                provisioned.upstream_setup.profile,
                provisioned.upstream_setup.binding.clone(),
            )
            .expect("the upstream setup is structurally sound"),
            ProductionSolanaLegSetupV1::new(
                ProductionRoutePositionV1::Downstream,
                provisioned.downstream_setup.profile,
                provisioned.downstream_setup.binding.clone(),
            )
            .expect("the downstream setup is structurally sound"),
        ],
    )
    .expect("a bundle of the same two setups");

    assert_eq!(
        decoded, rebuilt,
        "the file is not the pair of setups the leg established"
    );
    assert_eq!(decoded.solana_legs().len(), 2);
    // A route whose counterparty positions are both Solana has no leg of any other
    // family, and an empty set is how the bundle says so.
    assert!(decoded.legs().is_empty());
    assert!(decoded.bitcoin_legs().is_empty());
    assert!(decoded.monero_legs().is_empty());
}

/// The agreement `authenticate_participant_bundle` demands between each binding and
/// the REGISTRY -- not between the binding and itself.
///
/// The daemon refuses a Solana position unless the profile's program id is the escrow
/// program the registry names, the binding's program-data hash is the hash the
/// registry pins, the profile's network is the registry's network, and the profile
/// requires an immutable program. A binding that agreed only with the frozen terms
/// would pass nothing.
#[test]
fn each_binding_agrees_with_the_registry_and_not_merely_with_itself() {
    let provisioned = provision_all();
    let facts = provisioned.facts;
    for setup in [&provisioned.upstream_setup, &provisioned.downstream_setup] {
        assert_eq!(setup.profile.program_id.0, facts.escrow_program);
        assert_eq!(setup.binding.program_data_hash, facts.program_data_hash);
        assert_eq!(setup.profile.network as u8, facts.network as u8);
        assert!(
            setup.profile.require_immutable_program,
            "the daemon refuses a Solana position whose profile does not require an \
             immutable program, and SolanaAdapterProfileV1::new leaves it off for a \
             local validator -- so the provisioner must set it"
        );
        assert_eq!(setup.binding.program_id.0, facts.escrow_program);
    }
}

#[test]
fn the_dleq_is_present_and_bounded_as_the_constructor_requires() {
    let provisioned = provision_all();
    for setup in [&provisioned.upstream_setup, &provisioned.downstream_setup] {
        // `ProductionSolanaLegSetupV1::new` refuses an empty proof and one past the
        // frozen maximum. This is the material that authenticates the position, so
        // its presence is asserted rather than assumed from a successful build.
        assert!(!setup.binding.dleq.bundle.proof.is_empty());
        assert!(setup.binding.dleq.bundle.proof.len() <= xmr_dleq_sigma::MAX_PROOF_BYTES);
        assert_ne!(setup.binding.terms_hash, [0; 32]);
        assert_eq!(setup.binding.terms_hash, setup.terms_digest);
    }
}

/// The bindings are the last artifact the fixture provisions, so this is also the
/// running total, and it is asserted in exactly one place for that reason.
#[test]
fn binding_the_setups_turns_the_ninth_pin_into_a_measurement() {
    let provisioned = provision_all();
    assert_eq!(
        provisioned.plan.measured_pin_count(),
        9,
        "four from the registry, three from the terms, one from the roster, one here"
    );
    assert!(
        provisioned.plan.pins_are_placeholders(),
        "ten pins are still labels and the plan must keep saying so"
    );
}
