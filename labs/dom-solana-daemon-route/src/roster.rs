//! The Relay roster bundle: which two keys speak for each position.
//!
//! This artifact carries no secret and authorises no settlement by itself. What it
//! fixes is the exact BIP340 key each participant of each position signs Relay
//! envelopes with at a frozen snapshot, so a message from a key the roster does not
//! name is not a message from that participant.
//!
//! # Why it is derived from the terms and not chosen
//!
//! `validate_roster_terms` refuses the bundle unless, for both positions:
//!
//! * `leg.session_id == terms.session_id`;
//! * `leg.policy_version == terms.policy_version`;
//! * the two members' participant ids are exactly `terms.roster`, in that order;
//! * every member key passes `validate_xonly_key`.
//!
//! So the roster is a function of the terms plus a key per participant. It is built
//! that way here -- the terms are the input, not a second declaration of the same
//! facts -- which is why the one thing this module chooses is the keys.
//!
//! `validate_shape` adds its own rules, and they are the reason the members are not
//! interchangeable: the participant ids must be strictly ascending (which
//! `terms.roster` already is, because `SettlementTermsV1::validate` refuses an
//! unsorted roster), the two keys must differ, neither member may be an `Observer`,
//! and the two roles must differ. One initiator and one solver per position.

use std::path::Path;

use btc_crypto::SecpContext;
use dom_interopd::{
    ProductionRelayRosterBundleV1, ProductionRosterLegV1, ProductionRosterMemberV1,
    ProductionRoutePositionV1,
};
use kaystra_core::terms::SettlementTermsV1;
use relay::SenderRoleV1;
use sha2::{Digest, Sha256};

/// The one pin this artifact determines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvisionedRelayRosterV1 {
    /// Digest over both Relay wire contexts and roster snapshots.
    pub relay_binding_digest: [u8; 32],
}

/// A participant's BIP340 key at this snapshot.
///
/// Derived from the participant id under a domain, so a laboratory route has a
/// reproducible roster without a key ceremony. A real deployment takes the key from
/// the participant instead; the difference is that there the secret is theirs, and
/// here it is this function's -- which is the same difference the terms provisioner
/// already states about the condition scalar.
/// The label each position's roster keys are derived under.
///
/// Part of the derivation, so they are named once and used both by the roster and by the
/// ceremony's secrets. Two positions sharing a label would give a party one key for both.
pub const UPSTREAM_LABEL: &str = "upstream";
pub const DOWNSTREAM_LABEL: &str = "downstream";

/// One participant's Relay secret for one position.
///
/// Exposed because the Contracts bootstrap ceremony needs it: a party supplies a relay
/// secret for each leg it is in, and the ceremony refuses unless that secret's x-only
/// public key IS the key this leg's roster names for that party. The roster derives the
/// key from this scalar, so the two cannot disagree.
///
/// Per POSITION, not per party: the label is part of the derivation, so a party holds a
/// different secret upstream and downstream -- which is why the ceremony's secrets carry
/// one field for each.
///
/// A real deployment's participant holds its own scalar and this function does not exist
/// for them, exactly as with the condition scalar and the authority keys.
pub fn participant_relay_secret(participant: &[u8; 32], label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DOM-SOLANA-DAEMON-ROUTE/ROSTER-PARTICIPANT-SECRET/V1\0");
    hasher.update(participant);
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

fn participant_key(
    secp: &SecpContext,
    participant: &[u8; 32],
    label: &str,
) -> Result<[u8; 32], String> {
    let secret = participant_relay_secret(participant, label);
    let key = secp
        .xonly_public_key(&secret)
        .map_err(|error| format!("{label} roster key: {error:?}"))?;
    // The same check the daemon runs over every member of the decoded bundle.
    secp.validate_xonly_key(&key)
        .map_err(|error| format!("{label} roster key is not a valid BIP340 key: {error:?}"))?;
    Ok(key)
}

fn leg(
    secp: &SecpContext,
    position: ProductionRoutePositionV1,
    terms: &SettlementTermsV1,
    label: &str,
) -> Result<ProductionRosterLegV1, String> {
    let mut snapshot = Sha256::new();
    snapshot.update(b"DOM-SOLANA-DAEMON-ROUTE/ROSTER-SNAPSHOT/V1\0");
    snapshot.update(terms.session_id.0);
    let roster_snapshot: [u8; 32] = snapshot.finalize().into();

    // `terms.roster` is already strictly ascending, so member order follows it and
    // the roles follow the order: the lower id initiates, the higher solves. An
    // arbitrary assignment would encode differently for the same route.
    let members = [
        ProductionRosterMemberV1 {
            participant_id: terms.roster[0],
            xonly_key: participant_key(secp, &terms.roster[0].0, label)?,
            role: SenderRoleV1::Initiator,
        },
        ProductionRosterMemberV1 {
            participant_id: terms.roster[1],
            xonly_key: participant_key(secp, &terms.roster[1].0, label)?,
            role: SenderRoleV1::Solver,
        },
    ];
    Ok(ProductionRosterLegV1 {
        position,
        session_id: terms.session_id.0,
        roster_snapshot,
        policy_version: terms.policy_version,
        members,
    })
}

/// Build the bundle from the two frozen terms, write it, and return its pin.
pub fn provision(
    state_dir: &Path,
    relative: &str,
    network_id: [u8; 32],
    route_id: [u8; 32],
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
) -> Result<ProvisionedRelayRosterV1, String> {
    let secp = SecpContext::new(&[0x5a; 32]);
    let bundle = ProductionRelayRosterBundleV1::new(
        network_id,
        route_id,
        [
            leg(
                &secp,
                ProductionRoutePositionV1::Upstream,
                upstream,
                UPSTREAM_LABEL,
            )?,
            leg(
                &secp,
                ProductionRoutePositionV1::Downstream,
                downstream,
                DOWNSTREAM_LABEL,
            )?,
        ],
    )
    .map_err(|error| format!("roster bundle: {error:?}"))?;

    let bytes = bundle
        .canonical_bytes()
        .map_err(|error| format!("roster bytes: {error:?}"))?;
    crate::owner_only::write(&state_dir.join(relative), &bytes)?;

    Ok(ProvisionedRelayRosterV1 {
        relay_binding_digest: bundle
            .bundle_digest()
            .map_err(|error| format!("roster digest: {error:?}"))?,
    })
}
