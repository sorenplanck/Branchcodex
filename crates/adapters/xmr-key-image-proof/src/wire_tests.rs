use super::*;

#[test]
fn v23_framing_cannot_be_reinterpreted_as_legacy_or_accept_trailing_data() {
    let context = InputSpendContextV23 {
        network_genesis: [1; 32],
        route: [2; 32],
        session: [3; 32],
        terms: [4; 32],
        funding_tx: [5; 32],
        output_index: u64::MAX,
        sweep_tx: [6; 32],
        destination: destination_digest_v23("test mathematical scope only"),
        funded_amount: 100,
        fee: 1,
        action: InputSpendActionV23::Refund,
    };
    let encoded = context.canonical_bytes().unwrap();
    assert_eq!(encoded.len(), 249);
    assert_eq!(InputSpendContextV23::decode(&encoded).unwrap(), context);
    for bad_len in [0, 248] {
        assert!(InputSpendContextV23::decode(&encoded[..bad_len]).is_err());
    }
    let mut bad = encoded.clone();
    bad.push(0);
    assert!(InputSpendContextV23::decode(&bad).is_err());
    bad = encoded;
    bad[248] = 3;
    assert!(InputSpendContextV23::decode(&bad).is_err());
    // No proof envelope is manufactured here: arbitrary/legacy framing must fail.
    assert!(InputSpendEnvelopeV23::decode(&[0; INPUT_SPEND_ENVELOPE_BYTES_V23]).is_err());
    assert_ne!(
        destination_digest_v23("address"),
        destination_digest_v23("address\0")
    );
}

#[test]
fn proof_only_request_binds_height_fee_and_prior_build_without_v2_fallback() {
    let context = InputSpendContextV23 {
        network_genesis: [1; 32],
        route: [2; 32],
        session: [3; 32],
        terms: [4; 32],
        funding_tx: [5; 32],
        output_index: 1,
        sweep_tx: [6; 32],
        destination: [7; 32],
        funded_amount: 100,
        fee: 2,
        action: InputSpendActionV23::Claim,
    };
    let mut request = CachedInputProofRequestV23 {
        api_version: 23,
        build: (),
        context: context.canonical_bytes().unwrap(),
        funding_height: 100,
        max_fee: 2,
        auth_tag: [0; 32],
    };
    let original = request
        .canonical_auth_bytes(b"test non-secret prior request")
        .unwrap();
    request.funding_height += 1;
    assert_ne!(
        original,
        request
            .canonical_auth_bytes(b"test non-secret prior request")
            .unwrap()
    );
    request.funding_height -= 1;
    assert_ne!(
        original,
        request
            .canonical_auth_bytes(b"different prior request")
            .unwrap()
    );
    request.max_fee = 1;
    assert!(request.canonical_auth_bytes(b"prior request").is_err());
    request.max_fee = 2;
    request.api_version = 2;
    assert!(request.canonical_auth_bytes(b"prior request").is_err());
}
