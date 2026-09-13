//! Cheap admission regression: use the actual snapshot timestamp and checkpoint
//! producers, without generating 1003 coinbases, a graph, or a GPL sidecar.
use super::*;
use route_time_anchor::*;
use std::os::unix::fs::PermissionsExt;

const OBSERVED_AT: u64 = 1_000_010;
const BASELINE_TIP: u64 = 1003;

fn prove_at(
    registry: &deployment_registry::ResolvedRegistryV1,
    terms: &[SettlementTermsV1; 2],
    limits: RouteTimePolicyLimitsV2,
    now: u64,
) -> ColdStartResult<core::result::Result<u64, RouteTimeAnchorErrorV2>> {
    use xmr_graph_wallet_tests::native_observation_v23::NativeDomSnapshotV23;
    let policy =
        RouteTimePolicyV2::from_registry_dom_xmr_v23(registry, &terms[0], &terms[1], limits)?;
    let bindings = policy.checkpoint_bindings();
    let dom_anchor = BASELINE_TIP - u64::from(bindings[0].finality().min_confirmations - 1);
    let timestamp =
        NativeDomSnapshotV23::baseline_timestamp_v24(BASELINE_TIP, OBSERVED_AT, dom_anchor)?;
    let dom = signed_time_v23::observations::observation(
        dom_anchor,
        [0xa1; 32],
        [0xa0; 32],
        timestamp,
        BASELINE_TIP,
        [0xb1; 32],
        [0xc1; 32],
        limits,
    )?;
    // Public synthetic XMR headers use the same common tip for both legs. This
    // is not a funding proof; this test exercises only signed time admission.
    let xmr = signed_time_v23::observations::observation(
        199,
        [0xa2; 32],
        [0xa3; 32],
        OBSERVED_AT - 120,
        200,
        [0xb2; 32],
        [0xc2; 32],
        limits,
    )?;
    let evidence = RouteTimeEvidenceV2::new(
        &policy,
        1,
        OBSERVED_AT,
        limits.expires_at_seconds,
        [
            CanonicalTimeCheckpointV2::new(bindings[0], dom),
            CanonicalTimeCheckpointV2::new(bindings[1], xmr),
            CanonicalTimeCheckpointV2::new(bindings[2], xmr),
        ],
    )?;
    let secp = btc_crypto::SecpContext::new(&[0x74; 32]);
    let policy_authorities =
        deployment_registry::AuthoritySetV1::new(1, vec![secp.xonly_public_key(&[93; 32])?])?;
    let evidence_authorities =
        deployment_registry::AuthoritySetV1::new(1, vec![secp.xonly_public_key(&[94; 32])?])?;
    let signed_policy = SignedRouteTimePolicyV2::new(
        &policy,
        crate::route_time_test_common::sign_digest(
            &secp,
            &[[93; 32]],
            &policy.policy_digest()?,
            0x75,
        ),
    )?;
    let signed_evidence = SignedRouteTimeEvidenceV2::new(
        &evidence,
        crate::route_time_test_common::sign_digest(
            &secp,
            &[[94; 32]],
            &evidence.evidence_digest()?,
            0x76,
        ),
    )?;
    let config = RouteTimeAnchorStoreConfigV2::new(
        registry,
        &terms[0],
        &terms[1],
        &policy_authorities,
        &evidence_authorities,
        &secp,
    )?;
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let mut store =
        DurableRouteTimeAnchorStoreV2::create(&root.path().join("time.sqlite"), config)?;
    let policy_context = RouteTimePolicyVerificationContextV2::new(
        &policy_authorities,
        &secp,
        registry,
        &terms[0],
        &terms[1],
    );
    let evidence_context =
        RouteTimeEvidenceVerificationContextV2::new(policy_context, &evidence_authorities);
    store.install_policy(&signed_policy, policy_context, OBSERVED_AT)?;
    store.install_evidence(&signed_evidence, evidence_context, OBSERVED_AT)?;
    if let Err(error) = store.prove_route_ladder(evidence_context, OBSERVED_AT) {
        return Ok(Err(error));
    }
    let checkpoint = FrozenRouteTimeCheckpointV2::new(
        policy.route_scope_digest(),
        policy.policy_digest()?,
        evidence.evidence_digest()?,
        1,
    )?;
    // This is the same current-ancestry proof used by the production funding
    // guard, not merely a fresh admission or historical proof reconstruction.
    Ok(store
        .prove_current_route_ladder_from_checkpoint(checkpoint, evidence_context, now)
        .map(|current| current.valid_until_seconds()))
}

#[test]
fn native_deadline_admission_uses_snapshot_anchor_age_and_refuses_expired_v24(
) -> ColdStartResult<()> {
    let (registry, upstream, downstream) =
        crate::route_time_test_common::mainnet_registry_and_terms();
    let mut manifest = registry.manifest().clone();
    let mut terms = [upstream, downstream];
    let [upstream, downstream] = &mut terms;
    crate::production_xmr_native_registry_fixture_v23::configure_network(
        &mut manifest,
        [upstream, downstream],
        xmr_setup_profile::XmrNetwork::Mainnet,
    )?;
    let mut limits = live_bound_tests_v24::limits();
    limits.valid_from_seconds = OBSERVED_AT - 60;
    limits.expires_at_seconds = OBSERVED_AT + 21600;
    let timing = manifest.chains[0].profile.timing;
    limits.counterparty_margin_seconds =
        adapter_btc::timelock::minimum_safety_margin_seconds(&timing, &timing)?;
    assert_eq!(limits.counterparty_margin_seconds, 2180);
    manifest.valid_from = limits.valid_from_seconds;
    manifest.expires_at = limits.expires_at_seconds;
    let plan = NativeDeadlinePlanV23::new(&manifest, limits, BASELINE_TIP)?;
    assert_eq!(plan.dom, [46827, 22963]);
    let mut unsupported = limits;
    unsupported.max_evidence_age_seconds = 21_601;
    unsupported.expires_at_seconds = OBSERVED_AT + 21_601;
    assert!(NativeDeadlinePlanV23::new(&manifest, unsupported, BASELINE_TIP).is_err());
    unsupported.max_evidence_age_seconds = 0;
    assert!(NativeDeadlinePlanV23::new(&manifest, unsupported, BASELINE_TIP).is_err());
    assert!(NativeDeadlinePlanV23::new(&manifest, limits, 4096).is_err());
    // The campaign negotiates the complete history horizon. Its implementation
    // pages that history instead of increasing the production cursor tail.
    assert_eq!(plan.maximum_dom_height_v24(), 47083);
    assert_eq!(
        plan.dom[0].checked_add(256),
        Some(plan.maximum_dom_height_v24())
    );
    for (position, term) in terms.iter_mut().enumerate() {
        plan.terms(position, term);
    }
    let secp = btc_crypto::SecpContext::new(&[0x77; 32]);
    let authorities =
        deployment_registry::AuthoritySetV1::new(1, vec![secp.xonly_public_key(&[91; 32])?])?;
    let signed = deployment_registry::SignedRegistryV1::new(
        &manifest,
        crate::route_time_test_common::sign_digest(
            &secp,
            &[[91; 32]],
            &manifest.manifest_digest()?,
            0x78,
        )
        .into_iter()
        .map(|signature| deployment_registry::RegistrySignatureV1 {
            signer_index: signature.signer_index,
            signature: signature.signature,
        })
        .collect(),
    )?;
    let registry = signed.verify(
        &authorities,
        &secp,
        deployment_registry::RegistryValidationPolicyV1 {
            now_seconds: OBSERVED_AT,
            expected_network_id: manifest.network_id,
            minimum_epoch: manifest.epoch,
        },
    )?;
    assert_eq!(
        prove_at(&registry, &terms, limits, OBSERVED_AT)??,
        limits.expires_at_seconds
    );
    for elapsed in [40 * 60, 100 * 60, 21_599] {
        assert_eq!(
            prove_at(&registry, &terms, limits, OBSERVED_AT + elapsed)??,
            limits.expires_at_seconds
        );
    }
    // No clock override, evidence refresh, sleep or deadline renewal: the same
    // original signed evidence is current after 100 minutes, but not at six hours.
    assert!(matches!(
        prove_at(&registry, &terms, limits, OBSERVED_AT + 21_600)?,
        Err(RouteTimeAnchorErrorV2::PolicyExpired)
    ));
    terms[0].dom_leg.deadline = kaystra_core::types::TimelockSpec::BlockHeight { value: 3107 };
    terms[1].dom_leg.deadline = kaystra_core::types::TimelockSpec::BlockHeight { value: 1103 };
    assert!(matches!(
        prove_at(&registry, &terms, limits, OBSERVED_AT)?,
        Err(RouteTimeAnchorErrorV2::DeadlinePassed)
    ));
    Ok(())
}
