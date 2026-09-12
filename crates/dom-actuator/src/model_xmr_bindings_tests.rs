use super::*;
use crate::store::tests::{binding, TestResult};
use dom_scriptless_crypto::{XmrOrdinaryRecoveryKindV12 as Kind, XmrRecoveryGraphBindingV11};

fn graph(parent: DomSessionBindingV1) -> XmrRecoveryGraphBindingV11 {
    // Identity-only fixture; this does not claim graph or signing authority.
    XmrRecoveryGraphBindingV11 {
        chain_id: parent.chain_id(),
        session_id: parent.session_id(),
        terms_hash: parent.terms_digest(),
        funding_commitment: [2; 33],
        cancelled_commitment: [3; 33],
        refund_recipient_commitment: [4; 33],
        punish_recipient_commitment: [5; 33],
        claim_adaptor_point: [6; 33],
        refund_adaptor_point: [7; 33],
        cancel_height: 100,
        punish_height: 200,
        reveal_safety_blocks: 10,
        cancel_fee: 1,
        refund_fee: 1,
        punish_fee: 2,
    }
}

#[test]
fn xmr_auxiliary_bindings_preserve_authority_and_separate_rounds() -> TestResult {
    let parent = binding(1, 2)?;
    let graph = graph(parent);
    let cancel = parent.for_xmr_ordinary_recovery_v22(&graph, Kind::Cancel, [31; 32])?;
    let compensation =
        parent.for_xmr_ordinary_recovery_v22(&graph, Kind::Compensation, [31; 32])?;
    let changed_template = parent.for_xmr_ordinary_recovery_v22(&graph, Kind::Cancel, [32; 32])?;
    assert_ne!(cancel.session_id(), parent.session_id());
    assert_ne!(cancel.session_id(), compensation.session_id());
    assert_ne!(cancel.session_id(), changed_template.session_id());
    assert_eq!(
        cancel,
        parent.for_xmr_ordinary_recovery_v22(&graph, Kind::Cancel, [31; 32])?
    );
    for auxiliary in [cancel, compensation, changed_template] {
        // Compare all remaining authority fields, not a hand-picked subset.
        assert_eq!(
            DomSessionBindingV1 {
                session_id: parent.session_id,
                ..auxiliary
            },
            parent
        );
    }
    Ok(())
}

#[test]
fn xmr_auxiliary_binding_refuses_foreign_parent_and_recursive_derivation() -> TestResult {
    let parent = binding(1, 2)?;
    let original = graph(parent);
    for field in 0..3 {
        let mut foreign = original;
        match field {
            0 => foreign.chain_id[0] ^= 1,
            1 => foreign.session_id[0] ^= 1,
            _ => foreign.terms_hash[0] ^= 1,
        }
        assert_eq!(
            parent.for_xmr_ordinary_recovery_v22(&foreign, Kind::Cancel, [31; 32]),
            Err(DomActuatorError::CapabilityMismatch)
        );
    }
    assert_eq!(
        parent.for_xmr_ordinary_recovery_v22(&original, Kind::Cancel, [0; 32]),
        Err(DomActuatorError::CapabilityMismatch)
    );
    let auxiliary = parent.for_xmr_ordinary_recovery_v22(&original, Kind::Cancel, [31; 32])?;
    assert_eq!(
        auxiliary.for_xmr_ordinary_recovery_v22(&original, Kind::Cancel, [31; 32]),
        Err(DomActuatorError::CapabilityMismatch)
    );
    Ok(())
}

#[test]
fn xmr_cancelled_binding_preserves_v12_identity_and_parent_authority() -> TestResult {
    let parent = binding(1, 2)?;
    let cancelled = parent.for_xmr_cancelled_output_v22()?;
    let mut legacy = b"DOM-INTEROP/XMR-CANCELLED-OUTPUT-SESSION/V12\0".to_vec();
    legacy.extend_from_slice(&parent.chain_id());
    legacy.extend_from_slice(&parent.session_id());
    legacy.extend_from_slice(&parent.terms_digest());
    assert_eq!(
        cancelled.session_id(),
        *dom_crypto::blake2b_256(&legacy).as_bytes()
    );
    assert_ne!(cancelled.session_id(), parent.session_id());
    assert_eq!(cancelled, parent.for_xmr_cancelled_output_v22()?);
    assert_eq!(
        DomSessionBindingV1 {
            session_id: parent.session_id,
            ..cancelled
        },
        parent
    );
    let ordinary = parent.for_xmr_ordinary_recovery_v22(&graph(parent), Kind::Cancel, [31; 32])?;
    assert_ne!(cancelled.session_id(), ordinary.session_id());
    Ok(())
}
