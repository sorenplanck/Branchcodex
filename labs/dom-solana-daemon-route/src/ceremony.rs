//! The two Contracts bootstrap ceremony plans, one per participant.
//!
//! The Contracts bootstrap is the one artifact of this route that a provisioner cannot
//! write, because it is the output of a ceremony between the two participants. What a
//! provisioner CAN do is state the ceremony's inputs exactly, and that is what this module
//! emits: the plan `bootstrap_command_v13` reads, once per party.
//!
//! # Every field is something this crate already measured
//!
//! The plan is schema thirteen and carries the network id, the route id, the registry
//! authority-set and manifest digests, the minimum registry epoch, both terms digests, the
//! roster digest and the local participant id -- then paths to the authority bundle, the
//! registry store, both terms files, the roster, the identity authority and the budget
//! policy. Not one of those is a new decision: the registry provisioner measured the first
//! two digests, the terms provisioner the next two, the roster provisioner the fifth, and
//! the layout names every path.
//!
//! Which digest matters: `registry_authority_set_digest` is compared against
//! `authorities.registry().authority_set_digest()`, the DEPLOYMENT-REGISTRY domain -- not
//! the route-time domain that the two time pins use. The two are different values for the
//! same key set, and mixing them up cost a round of `PinMismatch` earlier in this crate.
//!
//! # What the two plans differ in, and what they must not
//!
//! One field: `local_participant_id`. Everything else is the route, and the route is the
//! same route for both parties. A pair of plans that differed anywhere else would be two
//! parties preparing two different ceremonies.
//!
//! # What this module does not do
//!
//! It does not run the ceremony. `bootstrap_command_v13` reads secrets from the process's
//! stdin and refuses a terminal, it requires a release build with the production feature,
//! and it is meant to be invoked once per party and repeated after the peer's public files
//! have been copied across. Driving that is an orchestration step, not a provisioning one,
//! and it holds each party's secret in that party's own invocation.

use std::path::{Path, PathBuf};

use crate::registry::ProvisionedSolanaRegistryV1;
use crate::roster::ProvisionedRelayRosterV1;
use crate::terms::ProvisionedRouteTermsV1;
use crate::SolanaRouteBootstrapPlanV1 as Layout;

/// Everything the two plans are built from.
#[derive(Clone, Copy, Debug)]
pub struct CeremonyPlanInputV1<'a> {
    /// The state directory, which must be absolute: the plan's paths are resolved by
    /// another process with its own working directory.
    pub state_dir: &'a Path,
    pub registry: &'a ProvisionedSolanaRegistryV1,
    pub terms: &'a ProvisionedRouteTermsV1,
    pub roster: &'a ProvisionedRelayRosterV1,
    /// The route identity, as declared with the other five identities.
    pub route_id: [u8; 32],
    /// The two parties, in the order the roster names them.
    pub parties: [[u8; 32]; 2],
}

/// Where the two plans were written, in party order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyPlansV1 {
    pub paths: [PathBuf; 2],
}

/// Write one party's secrets, as the ceremony reads them from stdin.
///
/// Three fields: the passphrase that opens the Contracts transport identity authority, and
/// one Relay secret per position. Both secrets are present because both parties are in both
/// legs of this route, and the ceremony checks that correspondence exactly -- a party
/// supplies a secret for a leg if and only if that leg's roster names it, and the secret's
/// x-only public key must be the key the roster names.
///
/// The secrets are lowercase hex of exactly sixty-four characters, which is what the
/// ceremony's own parser accepts, and they are written owner-only like every other file
/// this crate produces. They are laboratory material: a deployment's party holds its own
/// and types the passphrase itself, which is why the ceremony reads this from stdin rather
/// than from a path in the plan.
pub fn write_secrets(
    party: &[u8; 32],
    identity_passphrase: &str,
    out_dir: &Path,
    file_name: &str,
) -> Result<PathBuf, String> {
    crate::owner_only::directory(out_dir)?;
    let hex = |bytes: [u8; 32]| -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    };
    let secrets = serde_json::json!({
        "identity_passphrase": identity_passphrase,
        "upstream_relay_secret": hex(crate::roster::participant_relay_secret(
            party,
            crate::roster::UPSTREAM_LABEL,
        )),
        "downstream_relay_secret": hex(crate::roster::participant_relay_secret(
            party,
            crate::roster::DOWNSTREAM_LABEL,
        )),
    });
    let bytes =
        serde_json::to_vec(&secrets).map_err(|error| format!("ceremony secrets: {error}"))?;
    let path = out_dir.join(file_name);
    crate::owner_only::write(&path, &bytes)?;
    Ok(path)
}

/// Write one plan per party and return their paths.
pub fn write_plans(
    input: &CeremonyPlanInputV1<'_>,
    out_dir: &Path,
) -> Result<CeremonyPlansV1, String> {
    if !input.state_dir.is_absolute() {
        return Err(format!(
            "the ceremony resolves these paths in another process, so the state directory \
             must be absolute: {}",
            input.state_dir.display()
        ));
    }
    if input.parties[0] == input.parties[1] {
        return Err("a bilateral ceremony needs two distinct parties".to_owned());
    }
    crate::owner_only::directory(out_dir)?;

    let absolute = |relative: &str| -> String {
        input
            .state_dir
            .join(relative)
            .to_string_lossy()
            .into_owned()
    };
    let mut written = Vec::with_capacity(2);
    for (index, party) in input.parties.iter().enumerate() {
        let plan = serde_json::json!({
            "schema": 13,
            "network_id": input.registry.network_id,
            "route_id": input.route_id,
            "registry_authority_set_digest": input.registry.authority_set_digest,
            "registry_manifest_digest": input.registry.manifest_digest,
            "minimum_registry_epoch": input.registry.epoch,
            "terms_digests": [
                input.terms.upstream_terms_digest,
                input.terms.downstream_terms_digest,
            ],
            "roster_digest": input.roster.relay_binding_digest,
            "local_participant_id": party,
            "authority_bundle_file": absolute(Layout::relative(
                dom_interopd::ProductionPathRoleV1::RegistryAuthorities,
            )),
            "registry_store": absolute(Layout::relative(
                dom_interopd::ProductionPathRoleV1::RegistryStore,
            )),
            "terms_files": [
                absolute(Layout::relative(dom_interopd::ProductionPathRoleV1::UpstreamTerms)),
                absolute(Layout::relative(dom_interopd::ProductionPathRoleV1::DownstreamTerms)),
            ],
            "roster_file": absolute(Layout::relative(
                dom_interopd::ProductionPathRoleV1::RelayRoster,
            )),
            "identity_store": absolute(Layout::contracts_transport_identity_relative()),
            "budget_policy_file": absolute(Layout::contracts_budget_policy_relative()),
        });
        let bytes = serde_json::to_vec_pretty(&plan)
            .map_err(|error| format!("ceremony plan {index}: {error}"))?;
        let path = out_dir.join(format!("ceremony-plan-party-{index}.json"));
        crate::owner_only::write(&path, &bytes)?;
        written.push(path);
    }
    Ok(CeremonyPlansV1 {
        paths: written
            .try_into()
            .map_err(|_| "two ceremony plans".to_owned())?,
    })
}
