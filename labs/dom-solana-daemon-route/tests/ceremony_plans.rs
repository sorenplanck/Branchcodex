//! The two ceremony plans: what the Contracts bootstrap ceremony is told.
//!
//! The ceremony itself is not run here -- it needs a release build with the production
//! feature, secrets on the process's stdin, and one invocation per party with the peer's
//! public files copied across. What these tests establish is that the inputs it would be
//! given are the route this crate provisioned and not a description of some other one.

mod common;

use common::{provision_all, PARTY_A, PARTY_B};
use dom_solana_daemon_route::ceremony::{write_plans, CeremonyPlanInputV1};

fn plans(
    provisioned: &common::Provisioned,
) -> (tempfile::TempDir, serde_json::Value, serde_json::Value) {
    let root = provisioned
        .directory
        .path()
        .canonicalize()
        .expect("an absolute state directory");
    // Outside the state directory: a plan is provisioning output, not state the daemon
    // reads, and the directory it validates should hold only what it declares.
    let out_root = tempfile::tempdir().expect("a plan directory");
    let out = out_root.path().to_path_buf();
    let written = write_plans(
        &CeremonyPlanInputV1 {
            state_dir: &root,
            registry: &provisioned.registry,
            terms: &provisioned.plan.terms.expect("the provisioned terms"),
            roster: &provisioned.plan.roster.expect("the provisioned roster"),
            route_id: provisioned.plan.route_id,
            parties: [PARTY_A.0, PARTY_B.0],
        },
        &out,
    )
    .expect("both ceremony plans");

    let read = |index: usize| -> serde_json::Value {
        let bytes = std::fs::read(&written.paths[index]).expect("a written plan");
        serde_json::from_slice(&bytes).expect("a plan that parses")
    };
    (out_root, read(0), read(1))
}

#[test]
fn the_two_plans_differ_in_exactly_one_field() {
    let provisioned = provision_all();
    let (_out, mut a, b) = plans(&provisioned);

    assert_eq!(
        a["local_participant_id"],
        serde_json::json!(PARTY_A.0.to_vec())
    );
    assert_eq!(
        b["local_participant_id"],
        serde_json::json!(PARTY_B.0.to_vec())
    );

    // Everything else is the route, and the route is the same route for both parties. A
    // pair that differed anywhere else would be two parties preparing two ceremonies.
    a["local_participant_id"] = b["local_participant_id"].clone();
    assert_eq!(a, b, "the plans differ in more than the local participant");
}

#[test]
fn every_value_is_one_this_crate_measured() {
    let provisioned = provision_all();
    let (_out, plan, _) = plans(&provisioned);
    let terms = provisioned.plan.terms.expect("the terms");
    let roster = provisioned.plan.roster.expect("the roster");

    assert_eq!(plan["schema"], 13);
    assert_eq!(
        plan["network_id"],
        serde_json::json!(provisioned.registry.network_id.to_vec())
    );
    assert_eq!(
        plan["route_id"],
        serde_json::json!(provisioned.plan.route_id.to_vec())
    );
    // The DEPLOYMENT-REGISTRY domain digest, not the route-time one: the ceremony compares
    // it with authorities.registry().authority_set_digest(). The two are different values
    // for the same key set.
    assert_eq!(
        plan["registry_authority_set_digest"],
        serde_json::json!(provisioned.registry.authority_set_digest.to_vec())
    );
    assert_eq!(
        plan["registry_manifest_digest"],
        serde_json::json!(provisioned.registry.manifest_digest.to_vec())
    );
    assert_eq!(plan["minimum_registry_epoch"], provisioned.registry.epoch);
    assert_eq!(
        plan["terms_digests"],
        serde_json::json!([
            terms.upstream_terms_digest.to_vec(),
            terms.downstream_terms_digest.to_vec()
        ])
    );
    assert_eq!(
        plan["roster_digest"],
        serde_json::json!(roster.relay_binding_digest.to_vec())
    );
    // The optional Monero field is absent rather than null: this route has no Monero leg,
    // and the plan refuses unknown fields.
    assert!(plan.get("xmr_compensation_policy_files").is_none());
}

#[test]
fn every_path_the_plan_names_exists_and_is_absolute() {
    let provisioned = provision_all();
    let (_out, plan, _) = plans(&provisioned);

    let mut named: Vec<String> = Vec::new();
    for key in [
        "authority_bundle_file",
        "registry_store",
        "roster_file",
        "identity_store",
        "budget_policy_file",
    ] {
        named.push(
            plan[key]
                .as_str()
                .unwrap_or_else(|| panic!("{key} is a string"))
                .to_owned(),
        );
    }
    for value in plan["terms_files"].as_array().expect("two terms files") {
        named.push(value.as_str().expect("a string").to_owned());
    }

    assert_eq!(named.len(), 7);
    for path in named {
        let path = std::path::Path::new(&path);
        assert!(
            path.is_absolute(),
            "the ceremony resolves this in another process: {}",
            path.display()
        );
        assert!(path.exists(), "the plan names something absent: {}", path.display());
    }
}

#[test]
fn a_plan_pair_for_one_party_is_refused() {
    let provisioned = provision_all();
    let root = provisioned
        .directory
        .path()
        .canonicalize()
        .expect("an absolute state directory");
    let out = tempfile::tempdir().expect("a plan directory");
    let error = write_plans(
        &CeremonyPlanInputV1 {
            state_dir: &root,
            registry: &provisioned.registry,
            terms: &provisioned.plan.terms.expect("the terms"),
            roster: &provisioned.plan.roster.expect("the roster"),
            route_id: provisioned.plan.route_id,
            parties: [PARTY_A.0, PARTY_A.0],
        },
        out.path(),
    )
    .expect_err("a bilateral ceremony needs two parties");
    assert!(error.contains("two distinct parties"), "{error}");
}

/// The correspondence the ceremony checks, asserted where both sides are in hand.
///
/// A party supplies a Relay secret for a leg if and only if that leg's roster names it, and
/// the secret's x-only public key must BE the key the roster names. A mismatch is refused
/// by the ceremony as a binding failure, which says nothing about which of the four
/// (party, position) pairs is wrong.
#[test]
fn each_emitted_relay_secret_is_the_key_the_roster_names() {
    let provisioned = provision_all();
    let out = tempfile::tempdir().expect("a secrets directory");
    let secp = btc_crypto::SecpContext::new(&[0x5a; 32]);

    let bytes = std::fs::read(
        provisioned
            .directory
            .path()
            .join(common::RELAY_ROSTER),
    )
    .expect("the roster artifact");
    let roster = dom_interopd::ProductionRelayRosterBundleV1::decode_canonical(&bytes)
        .expect("the roster decodes");

    for (index, party) in [PARTY_A, PARTY_B].into_iter().enumerate() {
        let path = dom_solana_daemon_route::ceremony::write_secrets(
            &party.0,
            std::str::from_utf8(common::IDENTITY_PASSPHRASE).expect("a utf-8 passphrase"),
            out.path(),
            &format!("secrets-{index}.json"),
        )
        .expect("one party's secrets");
        let secrets: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("the secrets")).expect("json");

        for (field, leg) in [
            ("upstream_relay_secret", 0usize),
            ("downstream_relay_secret", 1),
        ] {
            let hex = secrets[field].as_str().expect("a hex string");
            assert_eq!(hex.len(), 64, "{field} is not the length the ceremony parses");
            assert!(
                hex.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{field} is not lowercase hex"
            );
            let mut secret = [0u8; 32];
            for (slot, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
                secret[slot] = u8::from_str_radix(
                    std::str::from_utf8(pair).expect("ascii"),
                    16,
                )
                .expect("a hex byte");
            }
            let public = secp
                .xonly_public_key(&secret)
                .expect("a valid BIP340 secret");
            let member = roster.legs()[leg]
                .members
                .iter()
                .find(|member| member.participant_id == party)
                .unwrap_or_else(|| panic!("{party:?} is not in leg {leg}"));
            assert_eq!(
                public, member.xonly_key,
                "the {field} does not open the key the roster names for this party"
            );
        }
    }
}
