//! Native C/D custody plus both encrypted wallets; no aggregate secret is recovered.
use super::*;
use dom_actuator::{
    DomActuatorStoreV1, DomParticipantWalletV1, DomWalletAuthorityBindingV1, DomWalletSessionLegV1,
    DomXmrGraphSharesRequestV22, DomXmrPayoutKindV22 as Payout, DomXmrPayoutProofRequestV22,
};
use dom_crypto::{
    pedersen::{BlindingFactor, Commitment},
    PublicKey,
};
use dom_wallet2::{BlockRef, Network, OutputOrigin, StoredOutput, WalletV2State};
use xmr_refund_policy::compensation::XmrCompensationPolicyV11;

#[path = "production_xmr_native_custody_fixture_v23.rs"]
pub(crate) mod native_custody_v23;
#[path = "production_xmr_native_funding_fixture_v23.rs"]
mod native_funding_v23;
#[path = "production_xmr_native_observation_v23_tests.rs"]
pub(super) mod native_observation_v23;
#[path = "production_xmr_native_role_fixture_v23.rs"]
mod native_role_v23;

fn completed_wallet_fixture(
    bounded: bool,
    native: Option<&native_custody_v23::NativeXmrSecretsFixtureV23>,
) -> (Fixture, Vec<u8>) {
    let f = fixture_with_xmr_context_v23(true, native);
    let f = configure_wallet_fixture_v23(f, bounded, |_, terms| {
        if let Some(native) = native {
            native.configure_terms(terms).unwrap();
        }
    });
    complete_fixture(f)
}

pub(super) fn configure_wallet_fixture_v23(
    f: Fixture,
    bounded: bool,
    configure: impl FnMut(usize, &mut SettlementTermsV1),
) -> Fixture {
    configure_wallet_fixture_with_policy_v23(f, bounded, configure, |_, _, _| {})
}

pub(super) fn configure_wallet_fixture_with_policy_v23(
    f: Fixture,
    bounded: bool,
    mut configure: impl FnMut(usize, &mut SettlementTermsV1),
    mut configure_policy: impl FnMut(usize, &mut SettlementTermsV1, &mut XmrCompensationPolicyV11),
) -> Fixture {
    let mut plans: [Plan; 2] = [0, 1]
        .map(|actor| serde_json::from_slice(&std::fs::read(&f.plan[actor]).unwrap()).unwrap());
    for leg in 0..2 {
        let path = plans[0].xmr_compensation_policy_files.as_ref().unwrap()[leg]
            .as_ref()
            .unwrap();
        let mut policy =
            XmrCompensationPolicyV11::from_bytes(&std::fs::read(path).unwrap()).unwrap();
        let mut terms =
            SettlementTermsV1::decode(&std::fs::read(&plans[0].terms_files[leg]).unwrap()).unwrap();
        terms.fee_limit.dom_max = 1_000_000;
        configure(leg, &mut terms);
        if bounded {
            policy.cooperative_window_blocks = 13;
            policy.compensation_height = 124;
            policy.bounded_availability_v23 = Some(
                xmr_refund_policy::compensation::XmrRecoveryAvailabilityV23 {
                    maximum_unavailability_blocks: 1,
                    observation_delay_blocks: 1,
                    cancel_inclusion_blocks: 1,
                    refund_inclusion_blocks: 1,
                },
            );
            terms.assurance_policy_hash = Some(policy.policy_hash().unwrap());
        }
        configure_policy(leg, &mut terms, &mut policy);
        // Fixture configuration may negotiate a different native principal
        // (the real-output Claim case does this to keep the fee bound
        // meaningful).  Freeze the corresponding canonical reduced quote
        // before hashing either the policy or the settlement terms.
        let dom_principal = u64::try_from(terms.dom_leg.amount).unwrap();
        let xmr_principal = u64::try_from(terms.counterparty_leg.amount).unwrap();
        let mut divisor_left = dom_principal;
        let mut divisor_right = xmr_principal;
        while divisor_right != 0 {
            let remainder = divisor_left % divisor_right;
            divisor_left = divisor_right;
            divisor_right = remainder;
        }
        policy.dom_principal_noms = dom_principal;
        policy.xmr_principal_piconero = xmr_principal;
        policy.quote_dom_numerator = dom_principal / divisor_left;
        policy.quote_xmr_denominator = xmr_principal / divisor_left;
        terms.assurance_policy_hash = Some(policy.policy_hash().unwrap());
        let validated = policy.validate_for(&terms).unwrap();
        let values = [
            policy.dom_principal_noms,
            validated.successful_change_noms(),
            validated.refund_payout_noms(),
            validated.compensation_payout_noms(),
        ];
        let commitments: [[u8; 33]; 4] = std::array::from_fn(|index| {
            let blinding =
                BlindingFactor::from_bytes([11 + index as u8 + 16 * leg as u8; 32]).unwrap();
            *Commitment::commit(values[index], &blinding).as_bytes()
        });
        policy.claim_principal_commitment = commitments[0];
        policy.claim_change_commitment = commitments[1];
        policy.refund_recipient_commitment = commitments[2];
        policy.compensation_recipient_commitment = commitments[3];
        terms.assurance_policy_hash = Some(policy.policy_hash().unwrap());
        policy.validate_for(&terms).unwrap();
        write(path, &policy.to_bytes().unwrap());
        write(
            &plans[0].terms_files[leg],
            &terms.canonical_bytes().unwrap(),
        );
        for plan in &mut plans {
            plan.terms_digests[leg] = terms.terms_hash().unwrap();
        }
    }
    for actor in 0..2 {
        write(&f.plan[actor], &serde_json::to_vec(&plans[actor]).unwrap());
    }
    f
}

fn point(key: &PublicKey) -> core::result::Result<Commitment, dom_core::DomError> {
    Commitment::from_compressed_bytes(&key.to_compressed_bytes())
}
fn negative(key: &PublicKey) -> core::result::Result<Commitment, dom_core::DomError> {
    let mut bytes = key.to_compressed_bytes();
    bytes[0] ^= 1;
    Commitment::from_compressed_bytes(&bytes)
}
fn opening_point(
    commitment: [u8; 33],
    value: u64,
) -> core::result::Result<Commitment, dom_core::DomError> {
    let c = Commitment::from_compressed_bytes(&commitment)?;
    if value == 0 {
        return Ok(c);
    }
    let known = BlindingFactor::from_bytes([1; 32])?;
    let known_point = point(
        dom_adaptor::SigningShareV1::from_be_bytes([1; 32])
            .map_err(|_| dom_core::DomError::Invalid("test public scalar".into()))?
            .public_key(),
    )?;
    let value_h = Commitment::commit(value, &known).sub(&known_point)?;
    c.sub(&value_h)
}

#[test]
fn v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses(
) -> core::result::Result<(), Box<dyn std::error::Error>> {
    run_wallet_graph_fixture(false)
}

#[test]
fn v23_two_wallets_and_native_cd_proofs_form_identical_graph_templates(
) -> core::result::Result<(), Box<dyn std::error::Error>> {
    run_wallet_graph_fixture(true)
}

/// Full native Store/wallet component; not daemon F6 admission or network funding.
#[test]
fn v23_native_two_leg_templates_custody_ready_and_bounded_funding(
) -> core::result::Result<(), Box<dyn std::error::Error>> {
    let profile =
        xmr_setup_profile::XmrAdapterProfileV1::new(xmr_setup_profile::XmrNetwork::Stagenet, 2, 2)?;
    run_native_xmr_graph_fixture_v23(
        native_custody_v23::NativeXmrSecretsFixtureV23::new(profile),
        |secrets, signed, terms, actors, work, roles| {
            let refund_hash =
                dom_adaptor::canonical_template_v1(signed.produced[0].graph().refund_template())?.1;
            // Explicit planned fixture identity, never an observed chain payment.
            let mut planned = terms[0].canonical_bytes()?;
            planned.extend_from_slice(&signed.produced[0].graph().binding().funding_commitment);
            let planned_hash = *dom_crypto::blake2b_256_tagged(
                "DOM/NativeXmrComponentFixture/PlannedXmrFunding/V23",
                &planned,
            )
            .as_bytes();
            let native = secrets.initialize_custody(
                &terms[0],
                refund_hash,
                planned_hash,
                "offline-native-component-fixture-destination".into(),
                actors,
                work,
            )?;
            native_funding_v23::custody_and_funding(signed, native, roles, work)
        },
    )
}

/// Real native Claim component with actual GPL output scan and local RPC snapshots.
/// Requires explicit helper/sidecar paths; no missing-dependency success or skip.
#[test]
fn v23_native_claim_six_messages_and_presignature_with_real_output_scan(
) -> core::result::Result<(), Box<dyn std::error::Error>> {
    let config = native_observation_v23::Configuration::require()?;
    let profile =
        xmr_setup_profile::XmrAdapterProfileV1::new(xmr_setup_profile::XmrNetwork::Stagenet, 2, 2)?;
    run_native_xmr_graph_fixture_v23(
        native_custody_v23::NativeXmrSecretsFixtureV23::new(profile)
            .with_funding_fee_cap_v23(10_000)?
            .with_claim_payout_v23()?,
        |secrets, signed, terms, actors, work, roles| {
            let mut funding = config.start(
                secrets.combined_spend_public_key_v23()?,
                u64::try_from(terms[0].counterparty_leg.amount)?,
                u64::try_from(terms[0].fee_limit.counterparty_max)?,
            )?;
            let refund_hash =
                dom_adaptor::canonical_template_v1(signed.produced[0].graph().refund_template())?.1;
            let native = secrets.initialize_custody(
                &terms[0],
                refund_hash,
                funding.hash(),
                funding.destination(),
                actors,
                work,
            )?;
            let (signed, native) =
                native_funding_v23::custody_and_funding_for_claim(signed, native, roles, work)?;
            native_observation_v23::run_claim(signed, native, work, &mut funding)
        },
    )
}

fn run_wallet_graph_fixture(bounded: bool) -> core::result::Result<(), Box<dyn std::error::Error>> {
    run_wallet_graph_fixture_inner(bounded, None, |_, _, _, _, _, _| Ok(()))
}

/// One fresh C/D pair feeds native recovery signing and the caller's custody/funding continuation.
pub(crate) fn run_native_xmr_graph_fixture_v23<F>(
    native: native_custody_v23::NativeXmrSecretsFixtureV23,
    continuation: F,
) -> core::result::Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(
        native_custody_v23::NativeXmrSecretsFixtureV23,
        crate::production_noise_relay::SignedNativeGraphFixtureV23,
        [SettlementTermsV1; 2],
        [[u8; 32]; 2],
        [&std::path::Path; 2],
        [dom_final_claim_binding::FinalClaimRoleBindingV1; 2],
    ) -> core::result::Result<(), Box<dyn std::error::Error>>,
{
    run_wallet_graph_fixture_inner(true, Some(native), continuation)
}

fn run_wallet_graph_fixture_inner<F>(
    bounded: bool,
    mut native: Option<native_custody_v23::NativeXmrSecretsFixtureV23>,
    continuation: F,
) -> core::result::Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(
        native_custody_v23::NativeXmrSecretsFixtureV23,
        crate::production_noise_relay::SignedNativeGraphFixtureV23,
        [SettlementTermsV1; 2],
        [[u8; 32]; 2],
        [&std::path::Path; 2],
        [dom_final_claim_binding::FinalClaimRoleBindingV1; 2],
    ) -> core::result::Result<(), Box<dyn std::error::Error>>,
{
    let started = std::time::Instant::now();
    let (f, artifact) = completed_wallet_fixture(bounded, native.as_ref());
    let mut continuation = Some(continuation);
    let result = (|| -> core::result::Result<(), Box<dyn std::error::Error>> {
        eprintln!("native graph: fixture ready after {:?}", started.elapsed());
        let legs: &[usize] = if native.is_some() { &[1, 0] } else { &[0] };
        let mut downstream_claim = None;
        for (leg_ordinal, &leg_index) in legs.iter().enumerate() {
            let mut graph_outputs = if bounded {
                let c = complete_native_proof_in_fixture_for_leg(
                    BootstrapProofCase::Collateral,
                    &f,
                    &artifact,
                    leg_index,
                );
                eprintln!(
                    "native graph: C leg={leg_index} ready after {:?}",
                    started.elapsed()
                );
                let d = complete_native_proof_in_fixture_for_leg(
                    BootstrapProofCase::Cancelled,
                    &f,
                    &artifact,
                    leg_index,
                );
                eprintln!(
                    "native graph: D leg={leg_index} ready after {:?}",
                    started.elapsed()
                );
                Some((c, d))
            } else {
                None
            };
            let mut retained_keys = [None; 2];
            for restart in 0..2 {
                let mut noise_graphs = Vec::new();
                let mut signing_wallets_v23 = Vec::new();
                for actor in 0..2 {
                    let plan: Plan = serde_json::from_slice(&std::fs::read(&f.plan[actor])?)?;
                    let secp = SecpContext::new(&[13; 32]);
                    let context = load_context(&plan, &secp, true)?;
                    let verified = authenticate_against_expected_v1(
                        &artifact,
                        &context.expected,
                        &context.rosters,
                        &secp,
                    )?;
                    let bindings = [0, 1].map(|leg| {
                        let position = context.rosters.legs()[leg]
                            .members
                            .iter()
                            .position(|m| m.participant_id.0 == plan.local_participant_id)
                            .unwrap();
                        context.bindings[leg][position]
                    });
                    let mut mounted = resume_completed_bootstrap_v13(
                        &f.work[actor].join(ARTIFACT),
                        &verified,
                        bindings,
                        &plan.identity_store,
                        b"test-passphrase-v13",
                    )?
                    .unwrap();
                    let c = &mut mounted._shares[leg_index];
                    let d = mounted._cancelled_shares[leg_index].as_ref().unwrap();
                    let terms =
                        SettlementTermsV1::decode(&std::fs::read(&plan.terms_files[leg_index])?)?;
                    let policy = context.xmr_policies[leg_index].as_ref().unwrap();
                    let local_funds = plan.local_participant_id == policy.policy().dom_funder;
                    let kinds = if local_funds {
                        [Payout::ClaimChange, Payout::Refund]
                    } else {
                        [Payout::ClaimPrincipal, Payout::Compensation]
                    };
                    // Match the daemon: one physical wallet and actuator journal
                    // per participant, with both immutable session authorities.
                    // Never clone a wallet after reservations have been retained.
                    let wallet_path = f.work[actor].join("graph-wallet.v3");
                    let store_path = f.work[actor].join("graph-actuator.sqlite");
                    let first_open = leg_ordinal == 0 && restart == 0;
                    if first_open {
                        let mut state =
                            WalletV2State::new(Network::Mainnet, bindings[leg_index].chain_id());
                        state.meta.last_reconciled_tip = 10;
                        for &wallet_leg in legs {
                            let wallet_policy = context.xmr_policies[wallet_leg].as_ref().unwrap();
                            let wallet_funds =
                                plan.local_participant_id == wallet_policy.policy().dom_funder;
                            let wallet_kinds = if wallet_funds {
                                [Payout::ClaimChange, Payout::Refund]
                            } else {
                                [Payout::ClaimPrincipal, Payout::Compensation]
                            };
                            for kind in wallet_kinds {
                                let (_, commitment, value) = kind.policy_payout(wallet_policy);
                                let scalar_tag = match kind {
                                    Payout::ClaimPrincipal => 11,
                                    Payout::ClaimChange => 12,
                                    Payout::Refund => 13,
                                    Payout::Compensation => 14,
                                } + 16 * wallet_leg as u8;
                                state.outputs.insert(StoredOutput::new_unconfirmed(
                                    commitment,
                                    value,
                                    [scalar_tag; 32],
                                    OutputOrigin::ReceiveSlate,
                                    false,
                                    None,
                                    1,
                                ))?;
                            }
                            if wallet_funds {
                                // Synthetic history input, unique for each route
                                // position; this is not evidence of a mined UTXO.
                                let blinding =
                                    BlindingFactor::from_bytes([31 + 16 * wallet_leg as u8; 32])?;
                                let mut input = StoredOutput::new_unconfirmed(
                                    *Commitment::commit(3_000_000, &blinding).as_bytes(),
                                    3_000_000,
                                    *blinding.as_bytes(),
                                    OutputOrigin::ReceiveSlate,
                                    false,
                                    None,
                                    1,
                                );
                                input.confirm(
                                    BlockRef {
                                        height: 2,
                                        hash: [32; 32],
                                    },
                                    2,
                                )?;
                                state.outputs.insert(input)?;
                            }
                        }
                        dom_wallet2::save_wallet_state(&state, &wallet_path, "graph-wallet-test")?;
                        std::fs::set_permissions(
                            &wallet_path,
                            std::fs::Permissions::from_mode(0o600),
                        )?;
                    }
                    let mut store = if first_open {
                        DomActuatorStoreV1::create(&store_path)?
                    } else {
                        DomActuatorStoreV1::open_existing(&store_path)?
                    };
                    // Both sessions use one durable lease clock; moving to the
                    // other leg must not rewind it or reuse an old lease nonce.
                    let now = 1_000 + leg_ordinal as u64 * 40_000 + restart * 20_000;
                    let lease = store.acquire_lease(
                        plan.local_participant_id,
                        [141 + actor as u8 + restart as u8 + 4 * leg_ordinal as u8; 32],
                        now,
                        10_000,
                    )?;
                    for binding in bindings {
                        store.bind_session(lease, binding, now)?;
                    }
                    let mut wallet = DomParticipantWalletV1::open_existing(
                        &wallet_path,
                        zeroize::Zeroizing::new("graph-wallet-test".into()),
                        DomWalletAuthorityBindingV1::new(bindings[0], bindings[1])?,
                    )?;
                    for kind in kinds {
                        let key: &[u8] = match kind {
                            Payout::ClaimPrincipal => b"xmr-payout-principal-v22",
                            Payout::ClaimChange => b"xmr-payout-change-v22",
                            Payout::Refund => b"xmr-payout-refund-v22",
                            Payout::Compensation => b"xmr-payout-compensation-v22",
                        };
                        let old = c.runtime_public_record_v16(key)?;
                        assert_eq!(old.is_some(), restart != 0);
                        let offer = wallet
                            .session(if leg_index == 0 {
                                DomWalletSessionLegV1::Upstream
                            } else {
                                DomWalletSessionLegV1::Downstream
                            })?
                            .prepare_xmr_payout_proof_v22(
                                &mut store,
                                lease,
                                DomXmrPayoutProofRequestV22 {
                                    terms: &terms,
                                    policy,
                                    kind,
                                    shared: &c.capability,
                                    retained: old.as_deref(),
                                    now_unix_ms: now + 1,
                                },
                            )?;
                        let bytes = offer.to_bytes()?;
                        if let Some(old) = old {
                            assert_eq!(old, bytes);
                        }
                        c.retain_runtime_public_v16(key, &bytes)?;
                    }
                    let mut shares = wallet
                        .session(if leg_index == 0 {
                            DomWalletSessionLegV1::Upstream
                        } else {
                            DomWalletSessionLegV1::Downstream
                        })?
                        .prepare_xmr_graph_shares_v22(
                            &mut store,
                            lease,
                            DomXmrGraphSharesRequestV22 {
                                terms: &terms,
                                policy,
                                collateral: &c.capability,
                                cancelled: &d.capability,
                                now_unix_ms: now + 1,
                            },
                        )?;
                    let c_point = point(c.capability.binding().share_point())?;
                    let d_point = point(d.capability.binding().share_point())?;
                    let offsets = shares.offsets().map(|offset| {
                        point(
                            dom_adaptor::SigningShareV1::from_be_bytes(offset)
                                .unwrap()
                                .public_key(),
                        )
                        .unwrap()
                    });
                    let mut funding = c_point.clone();
                    if let Some(reservation) = shares.funding() {
                        assert!(local_funds);
                        for input in reservation.reservation().outputs() {
                            funding =
                                funding.sub(&opening_point(input.commitment(), input.value())?)?;
                        }
                        if let Some(change) = reservation.change_commitment() {
                            funding =
                                funding.add(&opening_point(change, reservation.change_noms())?)?;
                        }
                    } else {
                        assert!(!local_funds);
                    }
                    funding = funding.sub(&offsets[0])?;
                    let (_, success_commitment, success_value) = kinds[0].policy_payout(policy);
                    let (_, recovery_commitment, recovery_value) = kinds[1].policy_payout(policy);
                    let success = opening_point(success_commitment, success_value)?;
                    let recovery = opening_point(recovery_commitment, recovery_value)?;
                    let expected = [
                        funding,
                        success.sub(&c_point)?.sub(&offsets[1])?,
                        d_point.sub(&c_point)?.sub(&offsets[2])?,
                        (if local_funds {
                            recovery.sub(&d_point)?
                        } else {
                            negative(d.capability.binding().share_point())?
                        })
                        .sub(&offsets[3])?,
                        (if !local_funds {
                            recovery.sub(&d_point)?
                        } else {
                            negative(d.capability.binding().share_point())?
                        })
                        .sub(&offsets[4])?,
                    ];
                    for (key, expected) in shares.public_keys().iter().zip(expected) {
                        assert_eq!(&key.to_compressed_bytes(), expected.as_bytes());
                    }
                    let old_funding = c.runtime_public_record_v16(b"xmr-funding-offer-v22")?;
                    assert_eq!(old_funding.is_some(), restart != 0);
                    let funding_offer = wallet
                        .session(if leg_index == 0 {
                            DomWalletSessionLegV1::Upstream
                        } else {
                            DomWalletSessionLegV1::Downstream
                        })?
                        .prepare_xmr_funding_offer_v22(
                            &mut store,
                            lease,
                            &terms,
                            policy,
                            old_funding.as_deref(),
                            now + 1,
                        )?;
                    if let Some(funding) = shares.funding() {
                        assert_eq!(funding_offer.fee(), funding.fee_noms());
                        let mut expected_inputs: Vec<_> = funding
                            .reservation()
                            .outputs()
                            .iter()
                            .map(|input| input.commitment())
                            .collect();
                        expected_inputs.sort();
                        assert_eq!(
                            funding_offer
                                .inputs()
                                .iter()
                                .map(|input| *input.commitment.as_bytes())
                                .collect::<Vec<_>>(),
                            expected_inputs
                        );
                        assert_eq!(
                            funding_offer
                                .change()
                                .map(|output| *output.commitment.as_bytes()),
                            funding.change_commitment()
                        );
                    } else {
                        assert!(funding_offer.inputs().is_empty());
                        assert!(funding_offer.change().is_none());
                        assert_eq!(funding_offer.fee(), 0);
                    }
                    let funding_bytes = funding_offer.to_bytes()?;
                    if let Some(old) = old_funding {
                        assert_eq!(old, funding_bytes);
                    }
                    c.retain_runtime_public_v16(b"xmr-funding-offer-v22", &funding_bytes)?;
                    let digest = shares.public_commitment_v22();
                    // Peer-side reconstruction uses only authenticated route scope
                    // and the decoded public funding offer, never wallet metadata.
                    use xmr_refund_policy::graph_contribution_digest_v22::{
                        XmrGraphContributionDigestV22, XmrGraphFundingDigestV22,
                    };
                    let peer_inputs: Vec<_> = funding_offer
                        .inputs()
                        .iter()
                        .map(|input| *input.commitment.as_bytes())
                        .collect();
                    let peer_digest = XmrGraphContributionDigestV22 {
                        scope: [
                            bindings[leg_index].chain_id(),
                            bindings[leg_index].route_id(),
                            bindings[leg_index].session_id(),
                            bindings[leg_index].terms_digest(),
                            plan.local_participant_id,
                        ],
                        keys: shares.public_keys(),
                        offsets: shares.offsets(),
                        funding: local_funds.then_some(XmrGraphFundingDigestV22 {
                            inputs: &peer_inputs,
                            change: funding_offer
                                .change()
                                .map(|output| *output.commitment.as_bytes()),
                            fee: funding_offer.fee(),
                        }),
                    }
                    .digest();
                    assert_eq!(peer_digest, digest);
                    for invalid in [&digest[..31], &[0u8; 33][..]] {
                        assert!(c
                            .retain_runtime_public_v16(b"xmr-graph-keys-v22", invalid)
                            .is_err());
                    }
                    if let Some(old) = retained_keys[actor] {
                        assert_eq!(digest, old);
                    }
                    retained_keys[actor] = Some(digest);
                    c.retain_runtime_public_v16(b"xmr-graph-keys-v22", &digest)?;
                    let old_proofs = c.runtime_public_record_v16(b"xmr-graph-proofs-v22")?;
                    assert_eq!(old_proofs.is_some(), restart != 0);
                    let proofs = shares.prove_public_commitment_v22(old_proofs.as_deref())?;
                    if let Some(old) = &old_proofs {
                        assert_eq!(&proofs, old);
                    }
                    let mut changed = proofs.clone();
                    changed[0] ^= 1;
                    assert!(shares.prove_public_commitment_v22(Some(&changed)).is_err());
                    assert!(shares
                        .prove_public_commitment_v22(Some(&proofs[..proofs.len() - 1]))
                        .is_err());
                    c.retain_runtime_public_v16(b"xmr-graph-proofs-v22", &proofs)?;
                    let old_packet = c.runtime_public_record_v16(b"xmr-graph-offer-v22")?;
                    assert_eq!(old_packet.is_some(), restart != 0);
                    let packet =
                        crate::production_xmr_graph_offer_v22::retain_local_graph_offer_v22(
                            c,
                            &shares,
                            bindings[leg_index],
                            &terms,
                            policy,
                        )?;
                    if let Some(old) = old_packet {
                        assert_eq!(old, packet);
                    }
                    if restart == 1 {
                        noise_graphs.push(
                            crate::production_noise_relay::ProductionNoiseGraphOfferV22::new(
                                bindings[leg_index].route_id(),
                                terms.clone(),
                                policy.clone(),
                                c.capability.binding().clone(),
                                packet.clone(),
                            )?,
                        );
                    }
                    use xmr_refund_policy::graph_offer_v22::{
                        XmrGraphOfferScopeV22, XmrGraphOfferV22,
                    };
                    let packet_scope = XmrGraphOfferScopeV22 {
                        chain: c.capability.binding().trusted_chain_id(),
                        route_id: bindings[leg_index].route_id(),
                        participant: plan.local_participant_id,
                        direction: c.capability.binding().role(),
                    };
                    let decode = |bytes: &[u8]| {
                        XmrGraphOfferV22::from_bytes(bytes, &terms, policy, &packet_scope)
                    };
                    let decoded = decode(&packet)?;
                    assert_eq!(decoded.to_bytes()?, packet);
                    assert_eq!(decoded.public_commitment(policy, &packet_scope), digest);
                    for position in [0, 8, 40, 205, 365] {
                        let mut changed = packet.clone();
                        changed[position] ^= 0x80;
                        assert!(decode(&changed).is_err());
                    }
                    let mut excessive = packet.clone();
                    excessive[690..694].copy_from_slice(&u32::MAX.to_le_bytes());
                    assert!(decode(&excessive).is_err());
                    assert!(decode(&packet[..packet.len() - 1]).is_err());
                    let mut trailing = packet.clone();
                    trailing.push(0);
                    assert!(decode(&trailing).is_err());
                    if let Some((native_c, native_d)) = graph_outputs.as_ref() {
                        // Scope from real C/D and signed policy; no purported template
                        // authority is manufactured for these absent/Created sessions.
                        let signed = policy.policy();
                        let graph = dom_scriptless_crypto::XmrRecoveryGraphBindingV11 {
                            chain_id: signed.dom_chain_id,
                            session_id: signed.session_id,
                            terms_hash: *policy.terms_hash(),
                            funding_commitment: *native_c[actor]
                                .as_ref()
                                .ok_or("missing C")?
                                .0
                                .aggregate_commitment(),
                            cancelled_commitment: *native_d[actor]
                                .as_ref()
                                .ok_or("missing D")?
                                .0
                                .aggregate_commitment(),
                            refund_recipient_commitment: signed.refund_recipient_commitment,
                            punish_recipient_commitment: signed.compensation_recipient_commitment,
                            claim_adaptor_point: terms.adaptor_point_sec1,
                            refund_adaptor_point: match native.as_ref() {
                                Some(native) => native.refund_point()?,
                                None => dom_adaptor::SigningShareV1::from_be_bytes([42; 32])?
                                    .public_key()
                                    .to_compressed_bytes(),
                            },
                            cancel_height: signed.cancel_height,
                            punish_height: signed.compensation_height,
                            reveal_safety_blocks: signed.reveal_safety_blocks,
                            cancel_fee: signed.cancel_fee_noms,
                            refund_fee: signed.refund_fee_noms,
                            punish_fee: signed.compensation_fee_noms,
                        };
                        assert_cancel_custody_refuses_unadmitted_sessions(
                            &mut shares,
                            bindings[leg_index],
                            &graph,
                        )?;
                    }
                    if bounded && restart == 1 {
                        // Preserve the wallet-owned excesses for the genuine three-edge
                        // signer fixture; bulk compatibility remains tested on restart0.
                        signing_wallets_v23.push((bindings[leg_index], shares));
                    } else {
                        let expected_parent = [
                            shares.public_keys()[0].clone(),
                            shares.public_keys()[1].clone(),
                            shares.public_keys()[3].clone(),
                        ];
                        let parent = shares.take_parent_shares_v22()?;
                        for (share, key) in [&parent.0, &parent.1, &parent.2]
                            .into_iter()
                            .zip(expected_parent)
                        {
                            assert_eq!(share.public_key_v12(), &key);
                        }
                        assert!(shares.take_parent_shares_v22().is_err());
                        assert!(shares.prove_public_commitment_v22(None).is_err());
                        assert_eq!(shares.prove_public_commitment_v22(Some(&proofs))?, proofs);
                    }
                    assert!(wallet
                        .session(if leg_index == 0 {
                            DomWalletSessionLegV1::Upstream
                        } else {
                            DomWalletSessionLegV1::Downstream
                        })?
                        .prepare_xmr_graph_shares_v22(
                            &mut store,
                            lease,
                            DomXmrGraphSharesRequestV22 {
                                terms: &terms,
                                policy,
                                collateral: &c.capability,
                                cancelled: &c.capability,
                                now_unix_ms: now + 2,
                            }
                        )
                        .is_err());
                    // Wallet, both C/D native owners and all stores drop before restart.
                }
                if restart == 1 {
                    let pair = noise_graphs
                        .try_into()
                        .map_err(|_| "two native graph offers required")?;
                    if let Some((c, d)) = graph_outputs.take() {
                        let work = [f.work[0].as_path(), f.work[1].as_path()];
                        let signing_wallets = signing_wallets_v23
                            .try_into()
                            .map_err(|_| "two retained wallet owners required")?;
                        if leg_index == 1 {
                            downstream_claim = Some(crate::production_noise_relay::ProductionNoiseGraphOfferV22::test_form_claim_template_hash_v23(
                            &pair, c, d, native.as_ref().ok_or("missing native T/U owner")?.refund_point()?,
                        ).map_err(|error| -> Box<dyn std::error::Error> { error })?);
                            drop(signing_wallets);
                        } else if let Some(native) = native.take() {
                            let refund_point = native.refund_point()?;
                            let signed = crate::production_noise_relay::ProductionNoiseGraphOfferV22::test_form_native_graphs_with_refund_point_v23(
                            &pair, work, policy(), c, d, signing_wallets, refund_point,
                        ).map_err(|error| -> Box<dyn std::error::Error> { error })?;
                            let plans: [Plan; 2] = [
                                serde_json::from_slice(&std::fs::read(&f.plan[0])?)?,
                                serde_json::from_slice(&std::fs::read(&f.plan[1])?)?,
                            ];
                            let terms = [
                                SettlementTermsV1::decode(&std::fs::read(
                                    &plans[0].terms_files[0],
                                )?)?,
                                SettlementTermsV1::decode(&std::fs::read(
                                    &plans[0].terms_files[1],
                                )?)?,
                            ];
                            let roles = native_role_v23::roles(
                                &signed,
                                &terms,
                                downstream_claim
                                    .ok_or("missing actual downstream Claim template")?,
                            )?;
                            // Read the same encrypted wallets after both session
                            // owners dropped, before handing control to the next
                            // runtime phase. Both sets of durable payout pins must
                            // survive; separate per-leg files cannot satisfy this.
                            let mut owned_payouts = std::collections::BTreeSet::new();
                            for actor in 0..2 {
                                let mut economic_commitments = std::collections::BTreeSet::new();
                                for leg in 0..2 {
                                    let policy_path = plans[actor]
                                        .xmr_compensation_policy_files
                                        .as_ref()
                                        .unwrap()[leg]
                                        .as_ref()
                                        .unwrap();
                                    let policy = XmrCompensationPolicyV11::from_bytes(
                                        &std::fs::read(policy_path)?,
                                    )?;
                                    let validated = policy.validate_for(&terms[leg])?;
                                    let local_funds = plans[actor].local_participant_id
                                        == terms[leg].dom_leg.refund_to.0;
                                    let kinds = if local_funds {
                                        [Payout::ClaimChange, Payout::Refund]
                                    } else {
                                        [Payout::ClaimPrincipal, Payout::Compensation]
                                    };
                                    for kind in kinds {
                                        let (_, commitment, _) = kind.policy_payout(&validated);
                                        assert!(economic_commitments.insert(commitment));
                                    }
                                }
                                assert_eq!(economic_commitments.len(), 4);
                                let state = dom_wallet2::load_wallet_state(
                                    &f.work[actor].join("graph-wallet.v3"),
                                    "graph-wallet-test",
                                )?;
                                let all_pins: Vec<_> = state
                                    .outputs
                                    .iter()
                                    .filter_map(|output| {
                                        output
                                            .payout_for()
                                            .map(|pin| (output.commitment, pin.prepare_digest()))
                                    })
                                    .collect();
                                let pins: Vec<_> = all_pins
                                    .iter()
                                    .copied()
                                    .filter(|(commitment, _)| {
                                        economic_commitments.contains(commitment)
                                    })
                                    .collect();
                                let funding_change_pins = terms
                                    .iter()
                                    .filter(|terms| {
                                        terms.dom_leg.refund_to.0
                                            == plans[actor].local_participant_id
                                    })
                                    .count();
                                assert_eq!(
                                    all_pins.len(),
                                    4 + funding_change_pins,
                                    "economic payouts and durable funding changes must remain distinct"
                                );
                                assert_eq!(
                                    pins.len(),
                                    4,
                                    "both legs require their own economic payout pair"
                                );
                                let digests: std::collections::BTreeSet<_> =
                                    pins.iter().map(|(_, digest)| *digest).collect();
                                assert_eq!(
                                    digests.len(),
                                    4,
                                    "economic payout authority cannot alias across legs"
                                );
                                for (commitment, _) in pins {
                                    assert!(
                                        owned_payouts.insert(commitment),
                                        "a payout cannot belong to both physical wallets"
                                    );
                                }
                                assert!(!f.work[actor].join("graph-wallet-leg1.v3").exists());
                                assert!(!f.work[actor].join("graph-actuator-leg1.sqlite").exists());
                            }
                            continuation
                                .take()
                                .ok_or("native continuation already consumed")?(
                                native,
                                signed,
                                terms,
                                [plans[0].local_participant_id, plans[1].local_participant_id],
                                work,
                                roles,
                            )?;
                        } else {
                            crate::production_noise_relay::ProductionNoiseGraphOfferV22::test_form_native_graphs_v23(
                            &pair, work, policy(), c, d, signing_wallets,
                        ).map_err(|error| -> Box<dyn std::error::Error> { error })?;
                        }
                    }
                    crate::production_noise_relay::ProductionNoiseGraphOfferV22::test_exchange_native_pair_v22(pair)
                .map_err(|error| -> Box<dyn std::error::Error> { error })?;
                }
            }
        }
        Ok(())
    })();
    if result.is_err() {
        // Synthetic test wallets only; retain the existing owner-only directory
        // for exact Store replay instead of regenerating the costly C/D proofs.
        let retained = f._root.keep();
        eprintln!(
            "native graph: failed fixture retained at {}",
            retained.display()
        );
    }
    result
}

// A real empty/Created Store is intentionally insufficient. This fixture never
// adds early, BP, template, signing, identity or bilateral-agreement authority.
fn assert_cancel_custody_refuses_unadmitted_sessions(
    shares: &mut dom_actuator::DomXmrGraphSigningSharesV22,
    binding: dom_actuator::DomSessionBindingV1,
    graph: &dom_scriptless_crypto::XmrRecoveryGraphBindingV11,
) -> core::result::Result<(), Box<dyn std::error::Error>> {
    use dom_scriptless_store::{
        ContractsSessionStoreV1, SessionChainProjectionV1, SessionIrreversibleV1, SessionPhaseV1,
        SessionRecordFieldsV1, SessionRecordV1, SessionTxObservationV1,
    };
    let template_hash = [0x63; 32];
    let kind = dom_scriptless_crypto::XmrOrdinaryRecoveryKindV12::Cancel;
    let auxiliary = binding.for_xmr_ordinary_recovery_v22(graph, kind, template_hash)?;
    for state in 0..3 {
        let directory = tempfile::tempdir()?;
        let root = std::sync::Arc::new(cap_std::fs::Dir::from_std_file(std::fs::File::open(
            directory.path(),
        )?));
        let store = ContractsSessionStoreV1::create_production(root, "custody", policy())?;
        if state != 0 {
            let initial = SessionRecordV1::new(
                SessionRecordFieldsV1 {
                    session_id: auxiliary.session_id(),
                    revision: 0,
                    phase: SessionPhaseV1::Created,
                    terms_hash: if state == 1 {
                        auxiliary.terms_digest()
                    } else {
                        [0xe2; 32]
                    },
                    transcript_hash: [0x71; 32],
                    irreversible: SessionIrreversibleV1 {
                        any_signing_share_sent: false,
                        funding_authorized: false,
                        adaptor_secret_exposed: false,
                        nonce_epoch: 1,
                    },
                    chain: SessionChainProjectionV1 {
                        tip_id: [0x72; 32],
                        tip_height: 10,
                        funding: SessionTxObservationV1::Unknown,
                        claim: SessionTxObservationV1::Unknown,
                        refund: SessionTxObservationV1::Unknown,
                    },
                },
                b"unadmitted-cancel-custody-negative",
            )?;
            store.create_session(&initial)?;
        }
        let before = shares.public_commitment_v22();
        assert!(shares
            .take_ordinary_share_v22(&store, graph, kind, template_hash)
            .is_err());
        assert_eq!(shares.public_commitment_v22(), before);
        // Fresh five-key PoPs require every private share still present.
        assert!(shares.prove_public_commitment_v22(None).is_ok());
    }
    Ok(())
}
