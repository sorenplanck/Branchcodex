//! Actual encrypted wallet and native reservation re-opened under a new lease.
use super::*;
use crate::model::StoredDomSessionBindingPartsV1;
use crate::DomParticipantV1;
use deployment_registry::{DomNetworkV1, DomRuntimeIdentityV1};
use dom_wallet2::{BlockRef, Network};
use std::os::unix::fs::PermissionsExt;

#[test]
fn xmr_collateral_reservation_restarts_with_exact_inputs_and_change(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut policy, mut terms) = fixture();
    terms.policy_version = dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17;
    terms.fee_limit.dom_max = 1_000_000;
    let amounts = policy.validate_for(&terms)?;
    let payout_openings = [
        (
            amounts.successful_change_noms(),
            BlindingFactor::from_bytes([83; 32])?,
        ),
        (
            amounts.refund_payout_noms(),
            BlindingFactor::from_bytes([84; 32])?,
        ),
    ];
    policy.claim_change_commitment =
        *Commitment::commit(payout_openings[0].0, &payout_openings[0].1).as_bytes();
    policy.refund_recipient_commitment =
        *Commitment::commit(payout_openings[1].0, &payout_openings[1].1).as_bytes();
    terms.assurance_policy_hash = Some(policy.policy_hash()?);
    let policy = policy.validate_for(&terms)?;
    let make_binding = |session_id, terms_digest| {
        DomSessionBindingV1::from_parts_for_store(StoredDomSessionBindingPartsV1 {
            route_id: [31; 32],
            session_id,
            participant: DomParticipantV1::new(policy.policy().dom_funder, 0)?,
            chain_id: terms.dom_leg.chain_id.0,
            genesis_hash: [32; 32],
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
            terms_digest,
            profile_digest: [33; 32],
            deployment_digest: [34; 32],
            asset_binding_digest: [35; 32],
            registry_epoch: 1,
            min_confirmations: 2,
            max_reorg_depth: 10,
        })
    };
    let binding = make_binding(terms.session_id.0, terms.terms_hash()?)?;
    let downstream = make_binding([36; 32], [37; 32])?;
    let authority = DomWalletAuthorityBindingV1::new(binding, downstream)?;
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let wallet_path = directory.path().join("wallet.v3");
    let store_path = directory.path().join("actuator.sqlite");
    let mut state = WalletV2State::new(Network::Regtest, binding.chain_id());
    state.meta.last_reconciled_tip = 10;
    let blinding = BlindingFactor::from_bytes([38; 32])?;
    let input = *Commitment::commit(3_000_000, &blinding).as_bytes();
    let mut output = StoredOutput::new_unconfirmed(
        input,
        3_000_000,
        *blinding.as_bytes(),
        OutputOrigin::ReceiveSlate,
        false,
        None,
        1,
    );
    output.confirm(
        BlockRef {
            height: 2,
            hash: [39; 32],
        },
        2,
    )?;
    state.outputs.insert(output)?;
    for (value, blinding) in &payout_openings {
        state.outputs.insert(StoredOutput::new_unconfirmed(
            *Commitment::commit(*value, blinding).as_bytes(),
            *value,
            *blinding.as_bytes(),
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1,
        ))?;
    }
    save_wallet_state(&state, &wallet_path, "xmr-test-password")?;
    fs::set_permissions(&wallet_path, fs::Permissions::from_mode(0o600))?;
    let mut store = DomActuatorStoreV1::create(&store_path)?;
    let lease = store.acquire_lease(policy.policy().dom_funder, [40; 32], 1_000, 10_000)?;
    store.bind_session(lease, binding, 1_000)?;
    let mut wallet = DomParticipantWalletV1::open_existing(
        &wallet_path,
        Zeroizing::new("xmr-test-password".into()),
        authority,
    )?;
    let before = fs::read(&wallet_path)?;
    assert!(wallet
        .session(DomWalletSessionLegV1::Upstream)?
        .prepare_funding_inputs_v16(&mut store, lease, &terms, 1_001)
        .is_err());
    assert_eq!(fs::read(&wallet_path)?, before);
    assert!(wallet
        .state
        .outputs
        .iter()
        .all(|output| output.reserved_for.is_none()));

    use crate::DomXmrPayoutKindV22 as Payout;
    let kinds = [Payout::ClaimChange, Payout::Refund];
    let mut payout_evidence = Vec::new();
    for kind in kinds {
        let face = wallet
            .session(DomWalletSessionLegV1::Upstream)?
            .authenticate_xmr_payout_face_v22(&mut store, lease, &terms, &policy, kind, 1_001)?;
        assert_ne!(face.binding().session_id(), binding.session_id());
        assert_ne!(
            face.binding().session_id(),
            binding.for_xmr_cancelled_output_v22()?.session_id()
        );
        payout_evidence.push((
            face.binding(),
            face.payout_commitment(),
            face.payout_value(),
            face.evidence_digest(),
        ));
    }
    assert_ne!(payout_evidence[0].0, payout_evidence[1].0);
    assert_ne!(payout_evidence[0].1, payout_evidence[1].1);
    assert_eq!(
        payout_evidence[0].1,
        policy.policy().claim_change_commitment
    );
    assert_eq!(
        payout_evidence[1].1,
        policy.policy().refund_recipient_commitment
    );
    assert!(wallet
        .session(DomWalletSessionLegV1::Upstream)?
        .authenticate_xmr_payout_face_v22(
            &mut store,
            lease,
            &terms,
            &policy,
            Payout::ClaimPrincipal,
            1_001
        )
        .is_err());

    let prepared = wallet
        .session(DomWalletSessionLegV1::Upstream)?
        .prepare_xmr_funding_inputs_v22(&mut store, lease, &terms, &policy, 1_001)?
        .ok_or(DomActuatorError::InsufficientFunds)?;
    assert_eq!(prepared.principal_noms(), policy.collateral_noms());
    assert_eq!(
        prepared.principal_noms() + prepared.fee_noms() + prepared.change_noms(),
        3_000_000
    );
    assert_eq!(prepared.reservation().outputs()[0].commitment(), input);
    use xmr_refund_policy::funding_offer_v22::XmrFundingOfferV22;
    let funding_offer = wallet
        .session(DomWalletSessionLegV1::Upstream)?
        .prepare_xmr_funding_offer_v22(&mut store, lease, &terms, &policy, None, 1_001)?;
    let funding_bytes = funding_offer.to_bytes()?;
    let wallet_before_refusal = fs::read(&wallet_path)?;
    for candidate in [
        XmrFundingOfferV22::new(
            &terms,
            &policy,
            policy.policy().dom_funder,
            funding_offer.inputs().to_vec(),
            None,
            funding_offer.fee(),
        )?,
        XmrFundingOfferV22::new(
            &terms,
            &policy,
            policy.policy().dom_funder,
            funding_offer.inputs().to_vec(),
            funding_offer.change().cloned(),
            funding_offer.fee() - 1,
        )?,
    ] {
        let candidate_bytes = candidate.to_bytes()?;
        assert!(matches!(
            wallet
                .session(DomWalletSessionLegV1::Upstream)?
                .prepare_xmr_funding_offer_v22(
                    &mut store,
                    lease,
                    &terms,
                    &policy,
                    Some(&candidate_bytes),
                    1_001
                ),
            Err(DomActuatorError::IdempotencyConflict)
        ));
        assert_eq!(fs::read(&wallet_path)?, wallet_before_refusal);
    }
    let reservation = prepared.reservation().clone();
    let public = (
        prepared.principal_noms(),
        prepared.fee_noms(),
        prepared.change_noms(),
        prepared.change_commitment(),
    );
    let change = prepared
        .change_commitment()
        .ok_or(DomActuatorError::WalletUnavailable)?;
    let private = Zeroizing::new(
        *wallet
            .state
            .outputs
            .get(&change)
            .ok_or(DomActuatorError::WalletUnavailable)?
            .blinding,
    );
    drop(wallet);
    drop(store);

    let before = fs::read(&wallet_path)?;
    let mut store = DomActuatorStoreV1::open_existing(&store_path)?;
    let lease = store.acquire_lease(policy.policy().dom_funder, [41; 32], 20_000, 10_000)?;
    let mut wallet = DomParticipantWalletV1::open_existing(
        &wallet_path,
        Zeroizing::new("xmr-test-password".into()),
        authority,
    )?;
    let resumed = wallet
        .session(DomWalletSessionLegV1::Upstream)?
        .prepare_xmr_funding_inputs_v22(&mut store, lease, &terms, &policy, 20_001)?
        .ok_or(DomActuatorError::InsufficientFunds)?;
    let resumed_offer = wallet
        .session(DomWalletSessionLegV1::Upstream)?
        .prepare_xmr_funding_offer_v22(
            &mut store,
            lease,
            &terms,
            &policy,
            Some(&funding_bytes),
            20_001,
        )?;
    assert_eq!(resumed_offer.to_bytes()?, funding_bytes);
    assert_eq!(resumed.reservation(), &reservation);
    assert_eq!(
        (
            resumed.principal_noms(),
            resumed.fee_noms(),
            resumed.change_noms(),
            resumed.change_commitment()
        ),
        public
    );
    for (index, kind) in kinds.into_iter().enumerate() {
        let face = wallet
            .session(DomWalletSessionLegV1::Upstream)?
            .authenticate_xmr_payout_face_v22(&mut store, lease, &terms, &policy, kind, 20_001)?;
        assert_eq!(
            (
                face.binding(),
                face.payout_commitment(),
                face.payout_value(),
                face.evidence_digest()
            ),
            payout_evidence[index]
        );
    }
    assert_eq!(wallet.state.outputs.len(), 4);
    assert_eq!(fs::read(&wallet_path)?, before);
    assert!(!before.windows(32).any(|bytes| bytes == &private[..]));
    assert!(!fs::read(&store_path)?
        .windows(32)
        .any(|bytes| bytes == &private[..]));
    let mut wrong = terms.clone();
    wrong.fee_limit.dom_max += 1;
    assert!(wallet
        .session(DomWalletSessionLegV1::Upstream)?
        .prepare_xmr_funding_inputs_v22(&mut store, lease, &wrong, &policy, 20_002)
        .is_err());
    assert_eq!(fs::read(&wallet_path)?, before);
    drop(wallet);
    drop(store);

    // Restore the encrypted pre-pin snapshot. It still contains the correct
    // openings, but must not be adopted over the active native preparations.
    let retained_wallet = directory.path().join("wallet.retained");
    fs::rename(&wallet_path, &retained_wallet)?;
    save_wallet_state(&state, &wallet_path, "xmr-test-password")?;
    fs::set_permissions(&wallet_path, fs::Permissions::from_mode(0o600))?;
    let stale_ciphertext = fs::read(&wallet_path)?;
    let mut store = DomActuatorStoreV1::open_existing(&store_path)?;
    let lease = store.acquire_lease(policy.policy().dom_funder, [42; 32], 40_000, 10_000)?;
    let mut wallet = DomParticipantWalletV1::open_existing(
        &wallet_path,
        Zeroizing::new("xmr-test-password".into()),
        authority,
    )?;
    for kind in kinds {
        assert!(wallet
            .session(DomWalletSessionLegV1::Upstream)?
            .authenticate_xmr_payout_face_v22(&mut store, lease, &terms, &policy, kind, 40_001)
            .is_err());
    }
    assert_eq!(fs::read(&wallet_path)?, stale_ciphertext);
    drop(wallet);
    drop(store);
    fs::rename(&wallet_path, directory.path().join("wallet.stale"))?;
    fs::rename(&retained_wallet, &wallet_path)?;
    assert_eq!(fs::read(&wallet_path)?, before);

    // The actual pinned wallet cannot re-create payout authority in a
    // replacement actuator database, even if its parent binding is copied.
    let mut replacement = DomActuatorStoreV1::create(&directory.path().join("replacement.sqlite"))?;
    let lease = replacement.acquire_lease(policy.policy().dom_funder, [43; 32], 60_000, 10_000)?;
    replacement.bind_session(lease, binding, 60_000)?;
    let mut wallet = DomParticipantWalletV1::open_existing(
        &wallet_path,
        Zeroizing::new("xmr-test-password".into()),
        authority,
    )?;
    for kind in kinds {
        assert!(wallet
            .session(DomWalletSessionLegV1::Upstream)?
            .authenticate_xmr_payout_face_v22(
                &mut replacement,
                lease,
                &terms,
                &policy,
                kind,
                60_001
            )
            .is_err());
    }
    assert_eq!(fs::read(&wallet_path)?, before);
    drop(wallet);
    drop(replacement);

    let mut store = DomActuatorStoreV1::open_existing(&store_path)?;
    let lease = store.acquire_lease(policy.policy().dom_funder, [44; 32], 80_000, 10_000)?;
    let mut wallet = DomParticipantWalletV1::open_existing(
        &wallet_path,
        Zeroizing::new("xmr-test-password".into()),
        authority,
    )?;
    for (index, kind) in kinds.into_iter().enumerate() {
        let face = wallet
            .session(DomWalletSessionLegV1::Upstream)?
            .authenticate_xmr_payout_face_v22(&mut store, lease, &terms, &policy, kind, 80_001)?;
        assert_eq!(face.evidence_digest(), payout_evidence[index].3);
    }
    assert_eq!(fs::read(&wallet_path)?, before);
    Ok(())
}
