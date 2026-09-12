//! Pure timing checks; no gate, journal or signing authority is synthesized.
use super::*;

fn binding(cancel: u64, safety: u64) -> Vec<u8> {
    let point = dom_adaptor::SigningShareV1::from_be_bytes([7; 32])
        .expect("fixed public test point")
        .public_key()
        .to_compressed_bytes();
    encode_xmr_graph_binding_v12(&dom_scriptless_crypto::XmrRecoveryGraphBindingV11 {
        chain_id: [1; 32],
        session_id: [2; 32],
        terms_hash: [3; 32],
        funding_commitment: point,
        cancelled_commitment: point,
        refund_recipient_commitment: point,
        punish_recipient_commitment: point,
        claim_adaptor_point: point,
        refund_adaptor_point: point,
        cancel_height: cancel,
        punish_height: u64::MAX,
        reveal_safety_blocks: safety,
        cancel_fee: 1,
        refund_fee: 1,
        punish_fee: 1,
    })
}

#[test]
fn negotiated_reveal_margin_closes_before_generic_finality_window() {
    let bytes = binding(100, 10);
    let check = |height| {
        require_f7_funding_windows_v23(100, 9, F7RecoveryProfileV23::XmrBounded, &bytes, height)
    };
    assert!(check(89).is_ok());
    assert!(matches!(
        check(90),
        Err(SessionStoreError::FundingAuthorityUnavailable)
    ));
    assert!(check(91).is_err());
    assert!(require_f7_funding_windows_v23(100, 9, F7RecoveryProfileV23::Legacy, &[], 90).is_ok());
}

#[test]
fn bounded_guard_preserves_the_stricter_dom_finality_margin() {
    let bytes = binding(100, 2);
    assert!(
        require_f7_funding_windows_v23(100, 12, F7RecoveryProfileV23::XmrBounded, &bytes, 87)
            .is_ok()
    );
    assert!(
        require_f7_funding_windows_v23(100, 12, F7RecoveryProfileV23::XmrBounded, &bytes, 88)
            .is_err()
    );
}

#[test]
fn overflow_and_malformed_binding_fail_without_legacy_fallback() {
    let bytes = binding(u64::MAX - 1, 10);
    assert!(require_f7_funding_windows_v23(
        u64::MAX,
        0,
        F7RecoveryProfileV23::XmrBounded,
        &bytes,
        u64::MAX - 5
    )
    .is_err());
    assert!(require_f7_funding_windows_v23(
        u64::MAX,
        10,
        F7RecoveryProfileV23::XmrBounded,
        &bytes,
        u64::MAX - 5
    )
    .is_err());
    let mut trailing = binding(100, 10);
    trailing.push(0);
    for malformed in [&[][..], &trailing[..], &trailing[..16]] {
        assert!(matches!(
            require_f7_funding_windows_v23(100, 9, F7RecoveryProfileV23::XmrBounded, malformed, 1),
            Err(SessionStoreError::Quarantined)
        ));
        assert!(
            require_f7_funding_windows_v23(100, 9, F7RecoveryProfileV23::Legacy, malformed, 1)
                .is_ok()
        );
    }
}
