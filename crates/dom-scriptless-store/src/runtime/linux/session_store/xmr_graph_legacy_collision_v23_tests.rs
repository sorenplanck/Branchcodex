//! Regression for the GraphU collision probe. No C/D proofs or signing
//! authority are needed to prove which retained filename is inspected.
use super::*;

#[test]
fn graph_refund_collision_checks_only_the_existing_plain_refund_profile() {
    for purpose in [PurposeV1::Refund, PurposeV1::RefundAdaptor] {
        assert_eq!(
            graph_legacy_collision_purpose_v23(purpose).unwrap(),
            PurposeV1::Refund,
        );
    }
    for purpose in [
        PurposeV1::Funding,
        PurposeV1::ClaimAdaptor,
        PurposeV1::Sponsor,
    ] {
        assert!(graph_legacy_collision_purpose_v23(purpose).is_err());
    }
}

#[test]
fn graph_refund_probe_uses_registered_01_and_never_registers_legacy_05() {
    let session = [0x71; 32];
    let plain = signing_binding_name(session, PurposeV1::Refund);
    let graph_probe = signing_binding_name(
        session,
        graph_legacy_collision_purpose_v23(PurposeV1::RefundAdaptor).unwrap(),
    );
    assert_eq!(graph_probe, plain);
    assert!(ValidatedComponent::registered(&graph_probe).is_ok());
    assert!(ValidatedComponent::registered(&format!(".{graph_probe}.staging")).is_ok());

    let forbidden = signing_binding_name(session, PurposeV1::RefundAdaptor);
    assert_ne!(forbidden, graph_probe);
    assert!(ValidatedComponent::registered(&forbidden).is_err());
    assert!(ValidatedComponent::registered(&format!(".{forbidden}.staging")).is_err());
}

#[test]
fn graph_refund_collision_name_does_not_alias_funding_or_claim() {
    let session = [0x72; 32];
    let collision = signing_binding_name(
        session,
        graph_legacy_collision_purpose_v23(PurposeV1::RefundAdaptor).unwrap(),
    );
    for independent in [PurposeV1::Funding, PurposeV1::ClaimAdaptor] {
        let name = signing_binding_name(session, independent);
        assert_ne!(name, collision);
        assert!(ValidatedComponent::registered(&name).is_ok());
    }
}
