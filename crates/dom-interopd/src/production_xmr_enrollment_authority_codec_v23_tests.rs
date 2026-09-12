//! Schema-only negatives. These public bytes are never passed off as admitted
//! setup, executable policy, a signer, or a daemon-ready scenario.
use super::*;
use serde_json::{json, Value};

fn wire_shape() -> Value {
    json!({
        "format": FORMAT,
        "settlement_id": vec![1u8;32], "session_id": vec![2u8;32],
        "chain_id": vec![3u8;32], "terms_hash": vec![4u8;32],
        "authority": {"family":"XMR_ENROLLMENT_V23", "parameters": {
            "compensation_policy": [], "local_participant_id": vec![5u8;32],
            "setup_binding_hash": vec![6u8;32], "refund_point_sec1": vec![2u8;33],
            "executor_profile_hash": vec![7u8;32], "refund_deadline": 200,
            "refund_destination": "schema-only-not-an-admitted-address",
            "secret_store": "secrets.sqlite", "sidecar_socket": "sidecar.sock",
            "sidecar_timeout_ms": 1000,
            "recovery_v23": {"directory":"custody", "sealing_key_file":"seal.key",
                "custody_id":vec![8u8;32], "nullifier_store":"nullifiers.sqlite"}
        }}
    })
}

#[test]
fn enrollment_wire_has_no_legacy_template_field_or_profile_fallback() {
    let value = wire_shape();
    let parsed: WireV11 = serde_json::from_value(value.clone()).expect("closed schema");
    let canonical = serde_json::to_vec(&parsed).expect("canonical public schema bytes");
    let roundtrip: WireV11 = serde_json::from_slice(&canonical).expect("roundtrip");
    assert_eq!(serde_json::to_vec(&roundtrip).expect("reencode"), canonical);
    assert!(matches!(
        roundtrip.authority,
        WireAuthorityV11::MoneroEnrollment(_)
    ));
    for end in [0, 1, canonical.len() - 1] {
        assert!(serde_json::from_slice::<WireV11>(&canonical[..end]).is_err());
    }
    let mut legacy_pin = value.clone();
    legacy_pin["authority"]["parameters"]["refund_template_hash"] = json!(vec![9u8; 32]);
    assert!(serde_json::from_value::<WireV11>(legacy_pin.clone()).is_err());
    let mut legacy_recovery = value.clone();
    legacy_recovery["authority"]["parameters"]["recovery_v22"] = json!({
        "directory":"custody", "sealing_key_file":"seal.key"
    });
    assert!(serde_json::from_value::<WireV11>(legacy_recovery).is_err());
    let mut missing_recovery = value.clone();
    missing_recovery["authority"]["parameters"]
        .as_object_mut()
        .expect("object")
        .remove("recovery_v23");
    assert!(serde_json::from_value::<WireV11>(missing_recovery).is_err());
    let mut downgraded = value;
    downgraded["authority"]["family"] = json!("XMR");
    assert!(serde_json::from_value::<WireV11>(downgraded).is_err());
    // Merely adding the old pin still cannot reinterpret new metadata as old authority.
    legacy_pin["authority"]["family"] = json!("XMR");
    assert!(serde_json::from_value::<WireV11>(legacy_pin).is_err());
}
