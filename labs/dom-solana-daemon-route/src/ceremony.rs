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

use btc_crypto::SecpContext;

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

/// Walk what `load_context` walks, and name the step that fails.
///
/// The ceremony reports `Binding` for every input disagreement it can have: a plan field
/// that is zero, an authority bundle that does not decode, an authority-set digest that is
/// not the one pinned, a registry that will not load or whose manifest is another one, a
/// roster whose digest or network or route is not the plan's, terms that are not canonical
/// or do not hash to their pin, and a roster leg that does not match its terms. One word for
/// nine conditions across seven files.
///
/// So the same sequence runs here, in the same order, with the same public APIs and the
/// REAL clock the ceremony uses -- and each step says which one it was. A provisioner that
/// emits a plan its own route cannot satisfy should find out while it still has both sides.
pub fn verify_plan(plan_path: &Path, now_seconds: u64) -> Result<(), String> {
    use deployment_registry::{RegistryStoreV1, RegistryValidationPolicyV1};
    use dom_interopd::{ProductionAuthorityBundleV1, ProductionRelayRosterBundleV1};
    use kaystra_core::terms::SettlementTermsV1;

    let plan: serde_json::Value = serde_json::from_slice(
        &std::fs::read(plan_path).map_err(|error| format!("read the plan: {error}"))?,
    )
    .map_err(|error| format!("parse the plan: {error}"))?;

    let digest = |key: &str| -> Result<[u8; 32], String> {
        let values = plan[key]
            .as_array()
            .ok_or_else(|| format!("{key} is not an array"))?;
        let mut out = [0u8; 32];
        if values.len() != 32 {
            return Err(format!("{key} is {} bytes, not 32", values.len()));
        }
        for (slot, value) in values.iter().enumerate() {
            out[slot] = u8::try_from(value.as_u64().ok_or_else(|| format!("{key} is not bytes"))?)
                .map_err(|_| format!("{key} has a value past a byte"))?;
        }
        Ok(out)
    };
    let path = |key: &str| -> Result<PathBuf, String> {
        Ok(PathBuf::from(
            plan[key]
                .as_str()
                .ok_or_else(|| format!("{key} is not a string"))?,
        ))
    };

    if plan["schema"].as_u64() != Some(13) {
        return Err("the plan is not schema 13".to_owned());
    }
    let network_id = digest("network_id")?;
    let route_id = digest("route_id")?;
    let epoch = plan["minimum_registry_epoch"]
        .as_u64()
        .ok_or_else(|| "minimum_registry_epoch is not a number".to_owned())?;
    for (name, value) in [
        ("network_id", network_id),
        ("route_id", route_id),
        ("local_participant_id", digest("local_participant_id")?),
    ] {
        if value == [0; 32] {
            return Err(format!("{name} is zero, which the ceremony refuses"));
        }
    }
    if epoch == 0 {
        return Err("minimum_registry_epoch is zero".to_owned());
    }

    let secp = SecpContext::new(&[0x5a; 32]);
    let bundle = ProductionAuthorityBundleV1::decode_canonical(
        &std::fs::read(path("authority_bundle_file")?)
            .map_err(|error| format!("read the authority bundle: {error}"))?,
    )
    .map_err(|error| format!("the authority bundle does not decode: {error:?}"))?;
    bundle
        .registry()
        .validate_with_context(&secp)
        .map_err(|error| format!("the registry authority set is invalid: {error:?}"))?;
    if bundle
        .registry()
        .authority_set_digest()
        .map_err(|error| format!("the registry authority digest: {error:?}"))?
        != digest("registry_authority_set_digest")?
    {
        return Err(
            "the plan pins another registry authority set; this is the deployment-registry \
             domain, not the route-time one"
                .to_owned(),
        );
    }

    let store = RegistryStoreV1::open_existing(&path("registry_store")?)
        .map_err(|error| format!("the registry store does not open: {error:?}"))?;
    let resolved = store
        .load_current(
            bundle.registry(),
            &secp,
            RegistryValidationPolicyV1 {
                // The clock the ceremony uses, not a trusted second from the plan.
                now_seconds,
                expected_network_id: network_id,
                minimum_epoch: epoch,
            },
        )
        .map_err(|error| format!("the registry does not load at {now_seconds}: {error:?}"))?
        .ok_or_else(|| {
            format!("the registry store holds no registry current at {now_seconds}")
        })?;
    if resolved.manifest_digest() != digest("registry_manifest_digest")? {
        return Err("the plan pins another registry manifest".to_owned());
    }

    let roster = ProductionRelayRosterBundleV1::decode_canonical(
        &std::fs::read(path("roster_file")?)
            .map_err(|error| format!("read the roster: {error}"))?,
    )
    .map_err(|error| format!("the roster does not decode: {error:?}"))?;
    if roster
        .bundle_digest()
        .map_err(|error| format!("the roster digest: {error:?}"))?
        != digest("roster_digest")?
    {
        return Err("the plan pins another roster".to_owned());
    }
    if roster.network_id() != network_id {
        return Err("the roster names another interop network".to_owned());
    }
    if roster.route_id() != route_id {
        return Err("the roster names another route".to_owned());
    }

    let terms_files = plan["terms_files"]
        .as_array()
        .ok_or_else(|| "terms_files is not an array".to_owned())?;
    let terms_digests = plan["terms_digests"]
        .as_array()
        .ok_or_else(|| "terms_digests is not an array".to_owned())?;
    for index in 0..2 {
        let file = terms_files
            .get(index)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("terms_files[{index}] is missing"))?;
        let bytes =
            std::fs::read(file).map_err(|error| format!("read terms_files[{index}]: {error}"))?;
        let terms = SettlementTermsV1::decode(&bytes)
            .map_err(|error| format!("terms_files[{index}] does not decode: {error:?}"))?;
        if terms
            .canonical_bytes()
            .map_err(|error| format!("terms_files[{index}] does not encode: {error:?}"))?
            != bytes
        {
            return Err(format!("terms_files[{index}] is not its own canonical bytes"));
        }
        let mut expected = [0u8; 32];
        let declared = terms_digests
            .get(index)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("terms_digests[{index}] is missing"))?;
        for (slot, value) in declared.iter().enumerate().take(32) {
            expected[slot] = u8::try_from(value.as_u64().unwrap_or(256)).unwrap_or(0);
        }
        if terms
            .terms_hash()
            .map_err(|error| format!("terms_files[{index}] hash: {error:?}"))?
            != expected
        {
            return Err(format!("the plan pins another digest for terms_files[{index}]"));
        }
        // What `ExpectedLegV1::from_authenticated` demands of the roster leg beside it.
        let leg = &roster.legs()[index];
        if leg.session_id != terms.session_id.0 {
            return Err(format!("roster leg {index} names another session"));
        }
        if leg.policy_version != terms.policy_version {
            return Err(format!("roster leg {index} names another policy version"));
        }
        if leg.members.map(|member| member.participant_id) != terms.roster {
            return Err(format!("roster leg {index} names other participants"));
        }
    }
    Ok(())
}

/// Walk what `execute` walks before it loads the context, and name the step that fails.
///
/// The preamble has its own refusals, all of them `Binding` as well: a plan path that is not
/// absolute, a secrets blob containing a backslash -- the fields are borrowed from the JSON,
/// so an escape sequence cannot be borrowed and is refused outright -- an empty or oversized
/// passphrase, a relay secret that is not sixty-four lowercase hex characters or is zero, and
/// two relay secrets that are equal.
///
/// The plan is also read under a sixteen-kilobyte bound, which is checked here because a
/// plan that grows past it fails as storage rather than as anything about the route.
pub fn verify_ceremony_inputs(
    plan_path: &Path,
    secrets_path: &Path,
    now_seconds: u64,
) -> Result<(), String> {
    if !plan_path.is_absolute() {
        return Err(format!(
            "the ceremony refuses a plan path that is not absolute: {}",
            plan_path.display()
        ));
    }
    let plan_bytes =
        std::fs::read(plan_path).map_err(|error| format!("read the plan: {error}"))?;
    if plan_bytes.len() > 16_384 {
        return Err(format!(
            "the plan is {} bytes and the ceremony reads at most 16384",
            plan_bytes.len()
        ));
    }

    let secret_bytes =
        std::fs::read(secrets_path).map_err(|error| format!("read the secrets: {error}"))?;
    if secret_bytes.contains(&b'\\') {
        return Err(
            "the secrets contain a backslash, which the ceremony refuses because it borrows \
             its fields straight out of the JSON"
                .to_owned(),
        );
    }
    let secrets: serde_json::Value = serde_json::from_slice(&secret_bytes)
        .map_err(|error| format!("the secrets do not parse: {error}"))?;
    let passphrase = secrets["identity_passphrase"]
        .as_str()
        .ok_or_else(|| "identity_passphrase is not a string".to_owned())?;
    if passphrase.is_empty() || passphrase.len() > 4096 {
        return Err(format!(
            "the passphrase is {} bytes; the ceremony takes 1 to 4096",
            passphrase.len()
        ));
    }

    let mut relay = Vec::new();
    for field in ["upstream_relay_secret", "downstream_relay_secret"] {
        let text = secrets[field]
            .as_str()
            .ok_or_else(|| format!("{field} is not a string"))?;
        if text.len() != 64 {
            return Err(format!("{field} is {} characters, not 64", text.len()));
        }
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!("{field} is not lowercase hex"));
        }
        if text.bytes().all(|byte| byte == b'0') {
            return Err(format!("{field} is zero, which the ceremony refuses"));
        }
        relay.push(text.to_owned());
    }
    if relay[0] == relay[1] {
        return Err(
            "both relay secrets are the same; the ceremony refuses a party holding one key \
             for both positions"
                .to_owned(),
        );
    }

    verify_plan(plan_path, now_seconds)
}
