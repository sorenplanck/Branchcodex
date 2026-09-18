//! Worst-case DOM/SOL ladder through the durable authority: the Solana drift
//! band is charged in full on both deadlines and the signed margin is exact.
use super::*;
use route_time_anchor::{
    DurableRouteTimeAnchorStoreV2, EvidenceInstallOutcomeV2, PolicyInstallOutcomeV2,
    RouteTimeAnchorStoreConfigV2, VerifiedRouteTimeLadderV2, SOLANA_CLOCK_DRIFT_SECONDS_V2,
};

fn prove(
    upstream_deadline: u64,
) -> TestResult<Result<VerifiedRouteTimeLadderV2, RouteTimeAnchorErrorV2>> {
    let sol = sol_fixture(common::mainnet_registry_and_terms())?;
    let mut upstream = sol.upstream;
    upstream.counterparty_leg.deadline = TimelockSpec::TimestampSeconds {
        value: upstream_deadline,
    };
    let policy = RouteTimePolicyV2::from_registry_dom_sol_v25(
        &sol.registry,
        &upstream,
        &sol.downstream,
        common::limits(),
    )?;
    let fixture = common::Fixture {
        secp: SecpContext::new(&[0x77; 32]),
        registry: sol.registry,
        upstream,
        downstream: sol.downstream,
        policy,
        policy_authorities: authority_set(&SecpContext::new(&[0x78; 32]), &common::POLICY_SECRETS)?,
        evidence_authorities: authority_set(
            &SecpContext::new(&[0x79; 32]),
            &common::EVIDENCE_SECRETS,
        )?,
    };
    let evidence = RouteTimeEvidenceV2::new(
        &fixture.policy,
        1,
        EVIDENCE_TIME,
        EVIDENCE_TIME + 300,
        shared_checkpoints(&fixture.policy),
    )?;
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )?;
    let mut store = DurableRouteTimeAnchorStoreV2::create(
        &directory.path().join("route-time-v2.sqlite"),
        config,
    )?;
    assert_eq!(
        store.install_policy(
            &common::signed_policy(&fixture),
            fixture.policy_context(),
            EVIDENCE_TIME,
        )?,
        PolicyInstallOutcomeV2::Installed
    );
    assert_eq!(
        store.install_evidence(
            &common::signed_evidence(&fixture, &evidence),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )?,
        EvidenceInstallOutcomeV2::Installed
    );
    Ok(store.prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME))
}

#[test]
fn solana_drift_band_is_charged_in_full_on_both_deadlines() -> TestResult<()> {
    let drift = SOLANA_CLOCK_DRIFT_SECONDS_V2;
    let margin = common::limits().counterparty_margin_seconds;
    assert_eq!(drift, 3_600);
    let tightest = SOL_DOWNSTREAM_DEADLINE + 2 * drift + margin;
    assert_eq!(tightest, SOL_UPSTREAM_DEADLINE);

    let proof = prove(tightest)??;
    let counterparty = proof.counterparty_proof();
    assert_eq!(
        counterparty.downstream.earliest_seconds,
        SOL_DOWNSTREAM_DEADLINE - drift
    );
    assert_eq!(
        counterparty.downstream.latest_seconds,
        SOL_DOWNSTREAM_DEADLINE + drift
    );
    assert_eq!(counterparty.upstream.earliest_seconds, tightest - drift);
    assert_eq!(counterparty.upstream.latest_seconds, tightest + drift);
    assert_eq!(counterparty.margin_seconds, margin);
    assert_eq!(
        counterparty.upstream.earliest_seconds,
        counterparty.downstream.latest_seconds + margin
    );
    let hub = proof.hub_proof();
    assert!(hub.upstream.earliest_seconds >= hub.downstream.latest_seconds + hub.margin_seconds);
    // The earliest DOM hub maturity bounds the proof, as in the legacy KAT.
    assert_eq!(proof.valid_until_seconds(), EVIDENCE_TIME + 90);

    // One second tighter would need a relaxed drift band or margin: refused.
    assert!(matches!(
        prove(tightest - 1)?,
        Err(RouteTimeAnchorErrorV2::UnsafeWindow)
    ));
    Ok(())
}
