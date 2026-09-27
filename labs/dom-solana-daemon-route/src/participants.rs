//! The participant bindings: one Solana setup per position, and the pin over both.
//!
//! This is the artifact the daemon authenticates a Solana position *with*. For an EVM
//! or a Bitcoin leg the bundle carries participant signatures; for Solana it carries
//! no signature at all, and `dom-interopd` says why in its own words: "the
//! authentication anchor is the cross-curve DLEQ inside the binding, which
//! `solana_profile::validate_setup` verifies against the frozen terms". So what this
//! module writes is exactly the two bindings the leg produced when it established
//! each position -- the DLEQ included -- and nothing is re-derived here.
//!
//! # What the daemon then checks, and why this artifact cannot fake it
//!
//! `authenticate_participant_bundle` resolves each position's chain through the
//! authenticated registry and, for a `ChainKindV1::Solana`, refuses unless the
//! binding's own fields agree with the *registry's* deployment rather than with each
//! other: the profile's program id must be the escrow program the registry names, the
//! binding's `program_data_hash` must be the hash the registry pins, the profile's
//! network must be the registry's network, and `require_immutable_program` must be
//! set. Then `validate_setup` verifies the DLEQ against the frozen terms, the adaptor
//! point, the closed role byte and the derived PDAs.
//!
//! None of that can be satisfied by writing a plausible file. It is satisfied because
//! the binding came from `SolanaLegV1::establish`, which built it from the same
//! cluster facts the registry entry was built from.
//!
//! # One export was missing
//!
//! `ProductionSolanaLegSetupV1` has a public constructor but was absent from
//! `dom-interopd`'s re-export list, while its Monero counterpart
//! `ProductionXmrLegSetupV1` was present. The type was therefore unnameable outside
//! the crate and a Solana participant bundle could not be built at all. Adding it to
//! that list is the one change this work makes to a shared crate: additive, no
//! behaviour altered, and necessary rather than convenient.

use std::path::Path;

use dom_interopd::{
    ProductionParticipantBindingBundleV1, ProductionRoutePositionV1, ProductionSolanaLegSetupV1,
};

use crate::terms::ProvisionedPositionV1;

/// The one pin this artifact determines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProvisionedParticipantBindingsV1 {
    pub participant_bindings_digest: [u8; 32],
}

/// Write both positions' setups as one bundle and return its pin.
///
/// The positions are supplied in route order and encoded in it: the constructor
/// refuses a bundle whose legs are not strictly ascending by position, because the
/// canonical bytes -- and therefore the pin -- would otherwise depend on the order a
/// caller happened to pass them in.
pub fn provision(
    state_dir: &Path,
    relative: &str,
    route_id: [u8; 32],
    upstream: &ProvisionedPositionV1,
    downstream: &ProvisionedPositionV1,
) -> Result<ProvisionedParticipantBindingsV1, String> {
    let solana_legs = vec![
        ProductionSolanaLegSetupV1::new(
            ProductionRoutePositionV1::Upstream,
            upstream.profile,
            upstream.binding.clone(),
        )
        .map_err(|error| format!("upstream solana setup: {error:?}"))?,
        ProductionSolanaLegSetupV1::new(
            ProductionRoutePositionV1::Downstream,
            downstream.profile,
            downstream.binding.clone(),
        )
        .map_err(|error| format!("downstream solana setup: {error:?}"))?,
    ];
    // No EVM and no Bitcoin legs: this route's counterparty positions are both
    // Solana, and an empty set is how the bundle says a chain family is not present.
    let bundle = ProductionParticipantBindingBundleV1::new_with_counterparty_bindings(
        route_id,
        Vec::new(),
        Vec::new(),
        solana_legs,
    )
    .map_err(|error| format!("participant bundle: {error:?}"))?;

    let bytes = bundle
        .canonical_bytes()
        .map_err(|error| format!("participant bundle bytes: {error:?}"))?;
    crate::owner_only::write(&state_dir.join(relative), &bytes)?;

    Ok(ProvisionedParticipantBindingsV1 {
        participant_bindings_digest: bundle
            .bundle_digest()
            .map_err(|error| format!("participant bundle digest: {error:?}"))?,
    })
}
