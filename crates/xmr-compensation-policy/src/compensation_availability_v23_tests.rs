use super::*;

fn fixture_v23() -> (XmrCompensationPolicyV11, SettlementTermsV1) {
    let (mut policy, mut terms) = tests::fixture();
    policy.bounded_availability_v23 = Some(XmrRecoveryAvailabilityV23 {
        maximum_unavailability_blocks: 4,
        observation_delay_blocks: 2,
        cancel_inclusion_blocks: 3,
        refund_inclusion_blocks: 5,
    });
    // Signed finality = 3 + 6. Before U: 4 + 2*2 + 3 + 9 = 20.
    // After U: 5 + 9 = 14. The total inequality is strictly below Hp.
    policy.cooperative_window_blocks = 20;
    policy.reveal_safety_blocks = 14;
    policy.compensation_height = 135;
    terms.assurance_policy_hash = Some(policy.policy_hash().unwrap());
    (policy, terms)
}

#[test]
fn v23_is_explicit_and_cannot_reinterpret_legacy_signed_terms() {
    let (policy, terms) = fixture_v23();
    assert!(policy.validate_for(&terms).is_ok());
    let bytes = policy.to_bytes().unwrap();
    assert_eq!(bytes.len(), XMR_COMPENSATION_POLICY_BYTES_V23);
    assert_eq!(&bytes[..8], b"DOMXCM23");
    assert_eq!(XmrCompensationPolicyV11::from_bytes(&bytes), Ok(policy));

    let mut legacy = policy;
    legacy.bounded_availability_v23 = None;
    let old_bytes = legacy.to_bytes().unwrap();
    assert_eq!(old_bytes.len(), XMR_COMPENSATION_POLICY_BYTES_V11);
    assert_eq!(&old_bytes[..8], b"DOMXCM11");
    assert_eq!(&bytes[8..old_bytes.len()], &old_bytes[8..]);
    assert_eq!(XmrCompensationPolicyV11::from_bytes(&old_bytes), Ok(legacy));
    let expected_old_hash: [u8; 32] = Sha256::new()
        .chain_update(b"DOM-INTEROP/XMR-DOM-COMPENSATION/POLICY/V11\0")
        .chain_update(&old_bytes)
        .finalize()
        .into();
    assert_eq!(legacy.policy_hash().unwrap(), expected_old_hash);
    assert_ne!(policy.policy_hash().unwrap(), expected_old_hash);
    let mut old_terms = terms.clone();
    old_terms.assurance_policy_hash = Some(expected_old_hash);
    assert_eq!(
        policy.validate_for(&old_terms),
        Err(XmrCompensationPolicyErrorV11::TermsMismatch)
    );
    assert_eq!(
        legacy.validate_for(&terms),
        Err(XmrCompensationPolicyErrorV11::TermsMismatch)
    );
}

#[test]
fn v23_decoder_rejects_truncation_trailing_and_version_substitution() {
    let (policy, _) = fixture_v23();
    let bytes = policy.to_bytes().unwrap();
    for length in 0..bytes.len() {
        assert!(XmrCompensationPolicyV11::from_bytes(&bytes[..length]).is_err());
    }
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(XmrCompensationPolicyV11::from_bytes(&extended).is_err());
    let mut changed = bytes;
    changed[..8].copy_from_slice(b"DOMXCM11");
    assert!(XmrCompensationPolicyV11::from_bytes(&changed).is_err());
}

#[test]
fn each_availability_bound_is_committed_and_cannot_be_changed_after_signing() {
    let (policy, terms) = fixture_v23();
    for field in 0..4 {
        let mut changed = policy;
        let budget = changed.bounded_availability_v23.as_mut().unwrap();
        let target = match field {
            0 => &mut budget.maximum_unavailability_blocks,
            1 => &mut budget.observation_delay_blocks,
            2 => &mut budget.cancel_inclusion_blocks,
            _ => &mut budget.refund_inclusion_blocks,
        };
        *target += 1;
        assert_ne!(
            policy.policy_hash().unwrap(),
            changed.policy_hash().unwrap()
        );
        assert_eq!(
            changed.validate_for(&terms),
            Err(XmrCompensationPolicyErrorV11::TermsMismatch)
        );
        *changed
            .bounded_availability_v23
            .as_mut()
            .map(|b| match field {
                0 => &mut b.maximum_unavailability_blocks,
                1 => &mut b.observation_delay_blocks,
                2 => &mut b.cancel_inclusion_blocks,
                _ => &mut b.refund_inclusion_blocks,
            })
            .unwrap() = 0;
        assert_eq!(
            changed.to_bytes(),
            Err(XmrCompensationPolicyErrorV11::InvalidBounds)
        );
    }
}

#[test]
fn both_dependent_transaction_reserves_are_required_even_after_resigning() {
    let (policy, mut terms) = fixture_v23();
    for phase in 0..2 {
        let mut short = policy;
        if phase == 0 {
            short.cooperative_window_blocks -= 1;
        } else {
            short.reveal_safety_blocks -= 1;
        }
        terms.assurance_policy_hash = Some(short.policy_hash().unwrap());
        assert_eq!(
            short.validate_for(&terms),
            Err(XmrCompensationPolicyErrorV11::RecoveryWindow)
        );
    }
    let mut equality = policy;
    equality.compensation_height = 134;
    assert_eq!(
        equality.to_bytes(),
        Err(XmrCompensationPolicyErrorV11::RecoveryWindow)
    );
    for phase in 0..3 {
        let mut overflow = policy.bounded_availability_v23.unwrap();
        match phase {
            0 => overflow.maximum_unavailability_blocks = u64::MAX,
            1 => overflow.observation_delay_blocks = u64::MAX,
            _ => overflow.refund_inclusion_blocks = u64::MAX,
        }
        assert_eq!(
            overflow.required_reserves(3, 6),
            Err(XmrCompensationPolicyErrorV11::RecoveryWindow)
        );
    }
}

#[test]
fn bounded_schedule_reserves_all_outage_splits_before_or_after_cancel() {
    let (policy, terms) = fixture_v23();
    let budget = policy.bounded_availability_v23.unwrap();
    assert_eq!(budget.required_reserves(3, 6), Ok((20, 14)));
    assert!(policy.validate_for(&terms).is_ok());
    // Finite arithmetic schedule model, not a real chain or finality proof.
    // Outage allowance is shared across both phases, never reset on restart.
    for before in 0..=budget.maximum_unavailability_blocks {
        for after in 0..=budget.maximum_unavailability_blocks - before {
            for first_observation in 0..=budget.observation_delay_blocks {
                for second_observation in 0..=budget.observation_delay_blocks {
                    let cancelled_final = policy.cancel_height
                        + before
                        + first_observation
                        + budget.cancel_inclusion_blocks
                        + 9;
                    let refund_disclosed = cancelled_final + after + second_observation;
                    assert!(
                        refund_disclosed + policy.reveal_safety_blocks < policy.compensation_height
                    );
                    assert!(
                        refund_disclosed + budget.refund_inclusion_blocks + 9
                            < policy.compensation_height
                    );
                }
            }
        }
    }
}
