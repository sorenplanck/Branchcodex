//! Cheap schema/projection regressions, never admitted economic authorities.
use super::*;
use serde_json::{json, Value};

fn template() -> Result<Value> {
    // Same public schema as production_xmr_enrollment_authority_codec_v23_tests.
    // Parse/serialize PARAMETERS using the production type, not a permissive
    // mock decoder. No DLEQ, store, signer or executable policy is constructed.
    let parameters: crate::production_universal_leg_authority::ProductionUniversalXmrEnrollmentAuthorityV23 =
        serde_json::from_value(json!({
            "compensation_policy": [1,2,3], "local_participant_id": vec![5u8;32],
            "setup_binding_hash": vec![6u8;32], "refund_point_sec1": vec![2u8;33],
            "executor_profile_hash": vec![7u8;32], "refund_deadline": 200,
            "refund_destination": "schema-only-not-an-admitted-address",
            "secret_store": "secrets.sqlite", "sidecar_socket": "sidecar.sock",
            "sidecar_timeout_ms": 1000,
            "recovery_v23": {"directory":"custody", "sealing_key_file":"seal.key",
                "custody_id":vec![8u8;32], "nullifier_store":"nullifiers.sqlite"}
        }))?;
    Ok(json!({
        "format":"DOM-INTEROPD-LEG-AUTHORITY-V11",
        "settlement_id":vec![1u8;32], "session_id":vec![2u8;32],
        "chain_id":vec![3u8;32], "terms_hash":vec![4u8;32],
        "authority":{"family":"XMR_ENROLLMENT_V23","parameters":parameters}
    }))
}

fn project(value: &Value) -> Result<Value> {
    let bytes = serde_json::to_vec(value)?;
    decode_leg_parameters_v24(&bytes, ProductionUniversalLegV11::bundle_digest(&bytes)?)
}

#[test]
fn nested_enrollment_parameters_roundtrip_through_real_codec_v24() -> Result<()> {
    let wire = template()?;
    assert!(wire.get("family").is_none());
    assert!(wire.get("parameters").is_none());
    let projected = project(&wire)?;
    assert_eq!(projected, wire["authority"]["parameters"]);
    let typed: crate::production_universal_leg_authority::ProductionUniversalXmrEnrollmentAuthorityV23 =
        serde_json::from_value(projected.clone())?;
    let canonical = serde_json::to_vec(&typed)?;
    let reopened: crate::production_universal_leg_authority::ProductionUniversalXmrEnrollmentAuthorityV23 =
        serde_json::from_slice(&canonical)?;
    assert_eq!(serde_json::to_vec(&reopened)?, canonical);
    assert_eq!(serde_json::to_value(reopened)?, projected);
    Ok(())
}

#[test]
fn root_discriminator_other_families_and_open_parameters_are_refused_v24() -> Result<()> {
    let original = template()?;
    for family in ["XMR", "EVM", "SOL", "BTC", "xmr_enrollment_v23", ""] {
        let mut wire = original.clone();
        wire["authority"]["family"] = json!(family);
        // A root-level correct tag must never mask a nested wrong family.
        wire["family"] = json!("XMR_ENROLLMENT_V23");
        assert!(project(&wire).is_err());
    }
    let mut root_only = original.clone();
    let nested = root_only
        .as_object_mut()
        .unwrap()
        .remove("authority")
        .unwrap();
    root_only["family"] = nested["family"].clone();
    root_only["parameters"] = nested["parameters"].clone();
    assert!(project(&root_only).is_err());
    for parameters in [Value::Null, json!([]), json!({})] {
        let mut wire = original.clone();
        wire["authority"]["parameters"] = parameters;
        assert!(project(&wire).is_err());
    }
    let mut unknown = original.clone();
    unknown["authority"]["parameters"]["refund_template_hash"] = json!(vec![9u8; 32]);
    assert!(project(&unknown).is_err());
    let mut missing = original;
    missing["authority"]["parameters"]
        .as_object_mut()
        .unwrap()
        .remove("recovery_v23");
    assert!(project(&missing).is_err());
    Ok(())
}

#[test]
fn manifest_digest_and_json_framing_remain_required_v24() -> Result<()> {
    let bytes = serde_json::to_vec(&template()?)?;
    let digest = ProductionUniversalLegV11::bundle_digest(&bytes)?;
    assert!(decode_leg_parameters_v24(&bytes, [0; 32]).is_err());
    let mut changed = bytes.clone();
    changed.push(b' ');
    assert!(decode_leg_parameters_v24(&changed, digest).is_err());
    for malformed in [&bytes[..1], &bytes[..bytes.len() - 1], b"{}{}".as_slice()] {
        let digest = ProductionUniversalLegV11::bundle_digest(malformed)?;
        assert!(decode_leg_parameters_v24(malformed, digest).is_err());
    }
    Ok(())
}
