//! Two-party D ceremony under real native vaults and restart-only mounting.
use super::*;
use xmr_refund_policy::compensation::XmrCompensationPolicyV11;

pub(super) fn configure_terms(
    root: &Path,
    terms: &mut [SettlementTermsV1; 2],
) -> [Option<PathBuf>; 2] {
    let mut paths = [None, None];
    for (leg, terms) in terms.iter_mut().enumerate() {
        use kaystra_core::types::{FinalityPolicyV1, LockMechanism, TimelockSpec};
        terms.dom_leg.mechanism = LockMechanism::DomAdaptor2of2;
        terms.counterparty_leg.mechanism = LockMechanism::CrossCurveSharedSpend;
        terms.dom_leg.amount = 152;
        terms.counterparty_leg.amount = 152;
        terms.dom_leg.deadline = TimelockSpec::BlockHeight { value: 100 };
        terms.dom_leg.finality = FinalityPolicyV1 {
            min_confirmations: 3,
            max_reorg_depth: 6,
        };
        terms.recovery.refund_before_funding = true;
        terms.fee_limit.dom_max = 10;
        terms.fee_limit.counterparty_max = 3;
        let point = |n| {
            dom_adaptor::SigningShareV1::from_be_bytes([n; 32])
                .unwrap()
                .public_key()
                .to_compressed_bytes()
        };
        let policy = XmrCompensationPolicyV11 {
            settlement_id: terms.settlement_id.0,
            session_id: terms.session_id.0,
            dom_chain_id: terms.dom_leg.chain_id.0,
            xmr_chain_id: terms.counterparty_leg.chain_id.0,
            dom_funder: terms.dom_leg.refund_to.0,
            xmr_funder: terms.dom_leg.beneficiary.0,
            claim_principal_commitment: point(11),
            claim_change_commitment: point(12),
            refund_recipient_commitment: point(13),
            compensation_recipient_commitment: point(14),
            quote_dom_numerator: 1,
            quote_xmr_denominator: 1,
            xmr_principal_piconero: 152,
            dom_principal_noms: 152,
            volatility_margin_bps: 2500,
            collateral_confirmations: 6,
            cancel_height: 100,
            compensation_height: 121,
            cooperative_window_blocks: 10,
            reveal_safety_blocks: 10,
            claim_fee_noms: 2,
            cancel_fee_noms: 3,
            refund_fee_noms: 2,
            compensation_fee_noms: 8,
            bounded_availability_v23: None,
        };
        terms.assurance_policy_hash = Some(policy.policy_hash().unwrap());
        policy.validate_for(terms).unwrap();
        let path = root.join(format!("xmr-policy-{leg}.bin"));
        write(&path, &policy.to_bytes().unwrap());
        paths[leg] = Some(path);
    }
    paths
}

#[test]
fn native_xmr_d_ceremony_restarts_and_refuses_missing_journal_or_substituted_policy() {
    let (f, artifact) = completed_fixture_with_xmr(true);
    for actor in 0..2 {
        let plan: Plan = serde_json::from_slice(&std::fs::read(&f.plan[actor]).unwrap()).unwrap();
        let secp = SecpContext::new(&[13; 32]);
        let context = load_context(&plan, &secp, true).unwrap();
        let verified =
            authenticate_against_expected_v1(&artifact, &context.expected, &context.rosters, &secp)
                .unwrap();
        let positions = [0, 1].map(|leg| {
            context.rosters.legs()[leg]
                .members
                .iter()
                .position(|m| m.participant_id.0 == plan.local_participant_id)
                .unwrap()
        });
        let bindings = [0, 1].map(|leg| context.bindings[leg][positions[leg]]);
        let mount = || {
            resume_completed_bootstrap_v13(
                &f.work[actor].join(ARTIFACT),
                &verified,
                bindings,
                &plan.identity_store,
                b"test-passphrase-v13",
            )
        };
        let mut owners = mount().unwrap().unwrap();
        let snapshot = [0, 1].map(|leg| {
            let d = owners._cancelled_shares[leg].as_ref().unwrap();
            let make_driver = |material| {
                crate::production_contracts::ProductionBootstrapLegV16::for_xmr_cancelled_v22(
                    bindings[leg],
                    context.chain,
                    context.rosters.legs()[leg],
                    context.xmr_policies[leg].as_ref().unwrap(),
                    material,
                )
            };
            assert!(make_driver(d).is_ok());
            let terms =
                SettlementTermsV1::decode(&std::fs::read(&plan.terms_files[leg]).unwrap()).unwrap();
            let make_collateral = |material, terms: &SettlementTermsV1| {
                crate::production_contracts::ProductionBootstrapLegV16::for_xmr_collateral_v22(
                    bindings[leg],
                    context.chain,
                    &verified.legs()[leg],
                    terms,
                    context.xmr_policies[leg].as_ref().unwrap(),
                    material,
                )
            };
            let collateral = make_collateral(&owners._shares[leg], &terms).unwrap();
            assert!(
                !collateral.complete(),
                "a constructed proof driver cannot authorize funding"
            );
            assert!(
                collateral
                    .with_wallet_templates_v17(&terms, &f.work[actor], 0, &owners._shares[leg],)
                    .is_err(),
                "ordinary V17 templates cannot replace the XMR recovery graph"
            );
            assert!(make_collateral(d, &terms).is_err());
            assert!(make_collateral(&owners._shares[1 - leg], &terms).is_err());
            let mut substituted_terms = terms.clone();
            substituted_terms.dom_leg.amount += 1;
            assert!(make_collateral(&owners._shares[leg], &substituted_terms).is_err());
            assert!(make_driver(&owners._shares[leg]).is_err());
            assert!(make_driver(owners._cancelled_shares[1 - leg].as_ref().unwrap()).is_err());
            assert_eq!(
                d.capability.binding().session_id(),
                &bindings[leg]
                    .for_xmr_cancelled_output_v22()
                    .unwrap()
                    .session_id()
            );
            assert_ne!(
                d.capability.binding().share_point(),
                owners._shares[leg].capability.binding().share_point()
            );
            (
                d.capability.binding().share_point().to_compressed_bytes(),
                *d.capsule.as_bytes(),
            )
        });
        for leg in 0..2 {
            let foreign = owners._shares[leg].capsule.clone();
            let d = owners._cancelled_shares[leg].as_mut().unwrap();
            let original = std::mem::replace(&mut d.capsule, foreign);
            assert!(
                crate::production_contracts::ProductionBootstrapLegV16::for_xmr_cancelled_v22(
                    bindings[leg],
                    context.chain,
                    context.rosters.legs()[leg],
                    context.xmr_policies[leg].as_ref().unwrap(),
                    d,
                )
                .is_err()
            );
            d.capsule = original;
        }
        assert!(mount().is_err());
        drop(owners);
        let reopened = mount().unwrap().unwrap();
        for leg in 0..2 {
            let d = reopened._cancelled_shares[leg].as_ref().unwrap();
            assert_eq!(
                snapshot[leg],
                (
                    d.capability.binding().share_point().to_compressed_bytes(),
                    *d.capsule.as_bytes()
                )
            );
        }
        drop(reopened);
        let path = f.work[actor].join(format!("cancelled-{}.sqlite", positions[0]));
        let saved = path.with_extension("retained");
        std::fs::rename(&path, &saved).unwrap();
        assert!(mount().is_err());
        assert!(!path.exists(), "missing D journal must not be recreated");
        std::fs::rename(&saved, &path).unwrap();
        let contracts_path = f.work[actor].join(format!("cancelled-contracts-{}", positions[0]));
        let saved_contracts = contracts_path.with_extension("retained");
        std::fs::rename(&contracts_path, &saved_contracts).unwrap();
        assert!(mount().is_err());
        assert!(
            !contracts_path.exists(),
            "missing D Contracts must not be recreated"
        );
        std::fs::rename(&saved_contracts, &contracts_path).unwrap();
        let policy_path = plan.xmr_compensation_policy_files.as_ref().unwrap()[0]
            .as_ref()
            .unwrap();
        let bytes = std::fs::read(policy_path).unwrap();
        let mut foreign = XmrCompensationPolicyV11::from_bytes(&bytes).unwrap();
        foreign.session_id[0] ^= 1;
        write(policy_path, &foreign.to_bytes().unwrap());
        assert!(mount().is_err());
        write(policy_path, &bytes);
        drop(mount().unwrap().unwrap());
    }
}
