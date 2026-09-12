use super::*;

fn frozen() -> FrozenBindingsV1 {
    FrozenBindingsV1 {
        terms_digest: [1; 32],
        profile_bundle_digest: [2; 32],
        deployment_bundle_digest: [3; 32],
    }
}

fn authority() -> ProductionHeightDeadlineAuthorityV23 {
    ProductionHeightDeadlineAuthorityV23 {
        route_id: [4; 32],
        frozen: frozen(),
        bindings: vec![
            HeightBinding {
                leg: LegIdV1::Upstream,
                chain_id: [5; 32],
                adapter_profile: [6; 32],
                dom: true,
                height: 100,
                context: [7; 32],
            },
            HeightBinding {
                leg: LegIdV1::Upstream,
                chain_id: [8; 32],
                adapter_profile: [9; 32],
                dom: false,
                height: 1_000,
                context: [10; 32],
            },
        ],
    }
}

#[test]
fn selected_height_observers_require_exact_coverage_before_rpc() {
    let mut authority = authority();
    let upstream = (LegIdV1::Upstream, [8; 32], [9; 32]);
    assert_eq!(
        authority.require_complete_source_scopes_v23(&[upstream]),
        Ok(())
    );
    for scopes in [
        vec![],
        vec![upstream, upstream],
        vec![(LegIdV1::Downstream, [8; 32], [9; 32])],
        vec![(LegIdV1::Upstream, [88; 32], [9; 32])],
        vec![(LegIdV1::Upstream, [8; 32], [99; 32])],
    ] {
        assert_eq!(
            authority.require_complete_source_scopes_v23(&scopes),
            Err(Error::Refused)
        );
    }
    let mut downstream = authority.bindings[1].clone();
    downstream.leg = LegIdV1::Downstream;
    authority.bindings.push(downstream);
    let downstream = (LegIdV1::Downstream, [8; 32], [9; 32]);
    assert_eq!(
        authority.require_complete_source_scopes_v23(&[upstream]),
        Err(Error::Refused)
    );
    assert_eq!(
        authority.require_complete_source_scopes_v23(&[upstream, upstream]),
        Err(Error::Refused)
    );
    assert_eq!(
        authority.require_complete_source_scopes_v23(&[upstream, downstream]),
        Ok(())
    );
    assert_eq!(
        authority.require_complete_source_scopes_v23(&[downstream, upstream]),
        Ok(())
    );
    authority.bindings.retain(|binding| binding.dom);
    assert_eq!(authority.require_complete_source_scopes_v23(&[]), Ok(()));
    assert_eq!(
        authority.require_complete_source_scopes_v23(&[upstream]),
        Err(Error::Refused)
    );
}

#[test]
fn dom_observation_eligibility_follows_only_bound_dom_height_deadlines() {
    let mut authority = authority();
    assert!(authority.has_dom_deadlines_v23());
    authority.bindings.retain(|binding| !binding.dom);
    assert!(!authority.has_dom_deadlines_v23());
    authority.bindings.clear();
    assert!(!authority.has_dom_deadlines_v23());
}

#[test]
fn native_deadlines_derive_from_authenticated_composition_and_separate_frozen_scope() {
    let (_directory, composition) = super::super::tests::authenticated_composition();
    let first =
        ProductionHeightDeadlineAuthorityV23::from_composition([4; 32], &composition, frozen())
            .unwrap();
    assert!(first.has_dom_deadlines_v23());
    for binding in &first.bindings {
        assert!([composition.upstream(), composition.downstream()]
            .into_iter()
            .any(|terms| {
                let leg = if binding.dom {
                    terms.dom_leg
                } else {
                    terms.counterparty_leg
                };
                leg.chain_id.0 == binding.chain_id
                    && leg.adapter_profile_hash == binding.adapter_profile
                    && leg.deadline
                        == TimelockSpec::BlockHeight {
                            value: binding.height,
                        }
            }));
    }
    let mut foreign = frozen();
    foreign.terms_digest = [22; 32];
    let changed =
        ProductionHeightDeadlineAuthorityV23::from_composition([4; 32], &composition, foreign)
            .unwrap();
    assert_eq!(first.bindings.len(), changed.bindings.len());
    for (original, altered) in first.bindings.iter().zip(&changed.bindings) {
        assert_ne!(original.context, altered.context);
    }
    assert!(matches!(
        ProductionHeightDeadlineAuthorityV23::from_composition(ZERO_DIGEST, &composition, frozen()),
        Err(Error::Refused)
    ));
}

#[test]
fn native_height_does_not_expire_before_exact_height_and_never_uses_wall_clock() {
    let authority = authority();
    assert!(authority.due([5; 32], true, None, 99).unwrap().is_empty());
    let dom = authority.due([5; 32], true, None, 100).unwrap();
    assert_eq!(dom.len(), 1);
    assert!(authority
        .due([8; 32], false, Some([9; 32]), 999)
        .unwrap()
        .is_empty());
    let xmr = authority.due([8; 32], false, Some([9; 32]), 1_000).unwrap();
    assert_eq!(xmr.len(), 1);
    assert_ne!(dom[0].event_id(), xmr[0].event_id());
    assert_eq!(xmr[0].route_id(), [4; 32]);
    assert_eq!(xmr[0].frozen_bindings(), &frozen());
}

#[test]
fn native_height_replay_keeps_event_and_reason_when_tip_advances() {
    let authority = authority();
    let original = authority.due([8; 32], false, Some([9; 32]), 1_000).unwrap();
    let restarted = authority.due([8; 32], false, Some([9; 32]), 1_100).unwrap();
    assert_eq!(original[0].event_id(), restarted[0].event_id());
    assert_eq!(original[0].reason_digest(), restarted[0].reason_digest());
    assert_ne!(original[0].event_id(), ZERO_DIGEST);
    assert_ne!(original[0].reason_digest(), ZERO_DIGEST);
}

#[test]
fn native_height_refuses_cross_chain_face_and_profile_substitution() {
    let authority = authority();
    for (chain, dom, profile) in [
        ([0; 32], true, None),
        ([5; 32], false, None),
        ([8; 32], true, None),
        ([8; 32], false, Some([6; 32])),
    ] {
        assert!(matches!(
            authority.due(chain, dom, profile, u64::MAX),
            Err(Error::Refused)
        ));
    }
}

#[test]
fn xmr_registry_height_identity_refuses_operational_hash_and_preserves_replay() {
    let mut authority = authority();
    let profile = chain_profile::ChainProfileV1 {
        chain_id: kaystra_core::types::ChainId([8; 32]),
        kind: ChainKindV1::Monero {
            network: MoneroNetworkV1::Mainnet,
        },
        timing: adapter_btc::timelock::ChainTimingBoundsV1 {
            min_block_seconds: 60,
            max_block_seconds: 180,
            max_reorg_seconds: 1080,
            observation_seconds: 5,
            broadcast_seconds: 5,
        },
        finality: kaystra_core::types::FinalityPolicyV1 {
            min_confirmations: 2,
            max_reorg_depth: 3,
        },
        native_asset: kaystra_core::types::AssetId([12; 32]),
        allowed_assets: vec![],
    };
    let digest = profile.profile_digest().unwrap();
    let operational =
        XmrAdapterProfileV1::new(xmr_setup_profile::XmrNetwork::Mainnet, 3, 2).unwrap();
    authority.bindings[1].adapter_profile = digest;
    assert_ne!(digest, operational.profile_hash());
    assert!(matches!(
        authority.due([8; 32], false, Some(operational.profile_hash()), 1000),
        Err(Error::Refused)
    ));
    assert!(authority
        .due([8; 32], false, Some(digest), 999)
        .unwrap()
        .is_empty());
    let first = authority.due([8; 32], false, Some(digest), 1000).unwrap();
    let replay = authority.due([8; 32], false, Some(digest), 1001).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].event_id(), replay[0].event_id());
    assert_eq!(first[0].reason_digest(), replay[0].reason_digest());
}

#[test]
fn same_chain_different_leg_profiles_keep_their_selected_observer_scope() {
    let mut authority = authority();
    let mut downstream = authority.bindings[1].clone();
    downstream.leg = LegIdV1::Downstream;
    downstream.adapter_profile = [44; 32];
    downstream.context = [45; 32];
    authority.bindings.push(downstream);
    let up = authority
        .due_for_leg(
            [8; 32],
            false,
            Some([9; 32]),
            1_000,
            Some(LegIdV1::Upstream),
        )
        .unwrap();
    let down = authority
        .due_for_leg(
            [8; 32],
            false,
            Some([44; 32]),
            1_000,
            Some(LegIdV1::Downstream),
        )
        .unwrap();
    assert_eq!(up.len(), 1);
    assert_eq!(down.len(), 1);
    assert_ne!(up[0].event_id(), down[0].event_id());
    assert!(matches!(
        authority.due_for_leg(
            [8; 32],
            false,
            Some([9; 32]),
            u64::MAX,
            Some(LegIdV1::Downstream)
        ),
        Err(Error::Refused)
    ));
}

#[test]
fn observer_unavailable_is_not_deadline_or_quorum_success() {
    assert_eq!(
        observer_error(XmrObserverError::RpcTransport),
        Error::Unavailable
    );
    assert_eq!(
        observer_error(XmrObserverError::ConflictingCanonicalTip),
        Error::Unavailable
    );
    assert_eq!(
        observer_error(XmrObserverError::WrongNetwork),
        Error::Refused
    );
    assert_eq!(
        observer_error(XmrObserverError::MalformedResponse),
        Error::Inconsistent
    );
    assert_eq!(
        dom_error(adapter_dom_real::RealDomError::Chain(
            dom_scriptless_chain_adapter::ChainAdapterError::IdentityMismatch
        )),
        Error::Refused
    );
    assert_eq!(
        dom_error(adapter_dom_real::RealDomError::InvalidEvidence),
        Error::Inconsistent
    );
}

#[test]
fn negotiated_sources_keep_remote_https_and_exact_node_count_and_quorum() {
    let profile = XmrAdapterProfileV1::new(xmr_setup_profile::XmrNetwork::Mainnet, 3, 2).unwrap();
    let urls = vec![
        "https://node-one.example:18081".to_owned(),
        "https://node-two.example:18081".to_owned(),
        "http://127.0.0.1:18083".to_owned(),
    ];
    assert_eq!(validate_source_urls(&profile, &urls), Ok(()));
    assert_eq!(
        validate_source_urls(&profile, &urls[..2]),
        Err(Error::Refused)
    );
    let mut duplicate = urls.clone();
    duplicate[1] = "https://NODE-ONE.example:18081/".to_owned();
    assert_eq!(
        validate_source_urls(&profile, &duplicate),
        Err(Error::Refused)
    );
    let mut plaintext = urls.clone();
    plaintext[0] = "http://node-one.example:18081".to_owned();
    assert_eq!(
        validate_source_urls(&profile, &plaintext),
        Err(Error::Refused)
    );
    let mut insufficient = profile;
    insufficient.rpc_quorum = 1;
    assert_eq!(
        validate_source_urls(&insufficient, &urls),
        Err(Error::Refused)
    );
}

#[test]
fn timestamp_schedule_delivers_once_and_reopen_does_not_replace_it() {
    use super::super::{ProductionDeadlineBindingV1, ProductionDeadlineTimerAuthorityV1};
    use crate::supervisor::{ManualClockV1, RouteSupervisorConfigV1, RouteSupervisorV1};
    use route_executor::{DurableRouteStoreV1, HealthStateV1, RouteEventV1, SecretVisibilityV1};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("route.sqlite3");
    let mut store = DurableRouteStoreV1::create(&path).unwrap();
    store.create_route([4; 32], 90).unwrap();
    let setup = store
        .acquire_lease([4; 32], [11; 32], 90, 100_000)
        .unwrap()
        .lease();
    store
        .apply_event(setup, 0, [12; 32], &RouteEventV1::FreezeTerms(frozen()), 90)
        .unwrap();
    let clock = ManualClockV1::new(100).unwrap();
    let config = RouteSupervisorConfigV1::new(100_000, 30_000, 1_000, 8).unwrap();
    let mut supervisor =
        RouteSupervisorV1::acquire(store, [4; 32], [11; 32], config, clock.clone()).unwrap();
    let mut timer = ProductionDeadlineTimerAuthorityV1::new(
        [4; 32],
        [ProductionDeadlineBindingV1::new([13; 32], 50_000).unwrap()],
    )
    .unwrap();
    timer.schedule_bound_deadlines(&mut supervisor).unwrap();
    let revision = supervisor.snapshot().unwrap().revision;
    timer.schedule_bound_deadlines(&mut supervisor).unwrap();
    assert_eq!(supervisor.snapshot().unwrap().revision, revision);
    assert_eq!(
        supervisor
            .dispatch_one_due_timer(&mut timer)
            .unwrap()
            .timers_completed,
        0
    );
    clock.set(50_000).unwrap();
    assert_eq!(
        supervisor
            .dispatch_one_due_timer(&mut timer)
            .unwrap()
            .timers_completed,
        1
    );
    let final_state = supervisor.snapshot().unwrap();
    assert_eq!(final_state.health, HealthStateV1::RecoveryOnly);
    assert_eq!(final_state.secret_visibility, SecretVisibilityV1::Private);
    assert!(!final_state.has_open_funds());
    drop(supervisor);
    clock.set(200_000).unwrap();
    let store = DurableRouteStoreV1::open_existing(&path).unwrap();
    let mut reopened = RouteSupervisorV1::acquire(store, [4; 32], [14; 32], config, clock).unwrap();
    timer.schedule_bound_deadlines(&mut reopened).unwrap();
    assert_eq!(reopened.snapshot().unwrap().revision, final_state.revision);
    assert_eq!(
        reopened
            .dispatch_one_due_timer(&mut timer)
            .unwrap()
            .timers_completed,
        0
    );
}
