use super::*;

#[test]
fn build_scope_has_no_future_hash_and_binds_session_authority_and_action() {
    let mut request = BuildSweepRequestV23 {
        api_version: 23,
        build: (),
        network_genesis: [1; 32],
        route: [2; 32],
        session: [3; 32],
        authorization_digest: [4; 32],
        request_message_digest: [6; 32],
        terms: [5; 32],
        output_index: 6,
        funding_height: 7,
        max_fee: 8,
        action: 1,
        auth_tag: [0; 32],
    };
    let original = request
        .canonical_auth_bytes(b"non-secret test nested encoding")
        .unwrap();
    request.session[0] ^= 1;
    assert_ne!(
        original,
        request
            .canonical_auth_bytes(b"non-secret test nested encoding")
            .unwrap()
    );
    request.session[0] ^= 1;
    request.authorization_digest[0] ^= 1;
    assert_ne!(
        original,
        request
            .canonical_auth_bytes(b"non-secret test nested encoding")
            .unwrap()
    );
    request.authorization_digest[0] ^= 1;
    request.request_message_digest[0] ^= 1;
    assert_ne!(
        original,
        request
            .canonical_auth_bytes(b"non-secret test nested encoding")
            .unwrap()
    );
    request.request_message_digest[0] ^= 1;
    request.action = 2;
    assert_ne!(
        original,
        request
            .canonical_auth_bytes(b"non-secret test nested encoding")
            .unwrap()
    );
    request.action = 3;
    assert!(request.validate_scope().is_err());
    request.action = 1;
    request.session = [0; 32];
    assert!(request.validate_scope().is_err());
    request.session = [3; 32];
    request.request_message_digest = [0; 32];
    assert!(request.validate_scope().is_err());
    request.request_message_digest = [6; 32];
    request.authorization_digest = [0; 32];
    assert!(request.validate_scope().is_err());
}
