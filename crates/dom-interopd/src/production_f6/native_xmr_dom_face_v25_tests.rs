//! Real public proofs; no mock provenance token or private peer wallet.
//! Noise/local/restart provenance is tested by the token's owning module.
use super::*;
use dom_adaptor::SigningShareV1;
use dom_crypto::{
    pedersen::{BlindingFactor, Commitment},
    recovery::RecoveryCapsule,
};
use kaystra_core::types::*;
use static_assertions::assert_not_impl_any;
use xmr_refund_policy::{
    compensation::{XmrCompensationPolicyV11, XmrRecoveryAvailabilityV23},
    economic_graph::{produce_xmr_payout_value_proof_v12, XmrPayoutValueProofV11},
};

assert_not_impl_any!(ProductionNativeXmrDomFaceOwnerV25: Clone, Copy, core::fmt::Debug);
assert_not_impl_any!(ProductionAuthenticatedXmrClaimPrincipalV25: Clone, Copy, core::fmt::Debug);

type TestResult = core::result::Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    terms: SettlementTermsV1,
    policy: ValidatedXmrCompensationPolicyV11,
    chain: TrustedChainIdV1,
    principal: XmrPolicyPayoutOfferV22,
}

impl Fixture {
    fn new() -> core::result::Result<Self, Box<dyn std::error::Error>> {
        let chain = TrustedChainIdV1::from_authenticated_genesis(
            0x000d_0012,
            &dom_core::Hash256::from_bytes([91; 32]),
        );
        let point = |value| -> core::result::Result<[u8; 33], Box<dyn std::error::Error>> {
            Ok(SigningShareV1::from_be_bytes([value; 32])?
                .public_key()
                .to_compressed_bytes())
        };
        let mut policy = XmrCompensationPolicyV11 {
            settlement_id: [1; 32],
            session_id: [2; 32],
            dom_chain_id: *chain.as_bytes(),
            xmr_chain_id: [4; 32],
            dom_funder: [5; 32],
            xmr_funder: [6; 32],
            claim_principal_commitment: point(7)?,
            claim_change_commitment: point(8)?,
            refund_recipient_commitment: point(9)?,
            compensation_recipient_commitment: point(10)?,
            quote_dom_numerator: 3,
            quote_xmr_denominator: 2,
            xmr_principal_piconero: 101,
            dom_principal_noms: 152,
            volatility_margin_bps: 2500,
            collateral_confirmations: 6,
            cancel_height: 100,
            compensation_height: 131,
            cooperative_window_blocks: 20,
            reveal_safety_blocks: 10,
            claim_fee_noms: 2,
            cancel_fee_noms: 3,
            refund_fee_noms: 2,
            compensation_fee_noms: 8,
            bounded_availability_v23: Some(XmrRecoveryAvailabilityV23 {
                maximum_unavailability_blocks: 1,
                observation_delay_blocks: 1,
                cancel_inclusion_blocks: 1,
                refund_inclusion_blocks: 1,
            }),
        };
        let finality = FinalityPolicyV1 {
            min_confirmations: 3,
            max_reorg_depth: 6,
        };
        let mut terms = SettlementTermsV1 {
            settlement_id: SettlementId(policy.settlement_id),
            session_id: SessionId(policy.session_id),
            intent_hash: IntentHash([11; 32]),
            solver_id: SolverId([12; 32]),
            roster: [
                ParticipantId(policy.dom_funder),
                ParticipantId(policy.xmr_funder),
            ],
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: ChainId(policy.dom_chain_id),
                asset_id: AssetId([13; 32]),
                amount: 152,
                beneficiary: ParticipantId(policy.xmr_funder),
                refund_to: ParticipantId(policy.dom_funder),
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight { value: 100 },
                finality,
                adapter_profile_hash: [14; 32],
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: ChainId(policy.xmr_chain_id),
                asset_id: AssetId([15; 32]),
                amount: 101,
                beneficiary: ParticipantId(policy.dom_funder),
                refund_to: ParticipantId(policy.xmr_funder),
                mechanism: LockMechanism::CrossCurveSharedSpend,
                deadline: TimelockSpec::TimestampSeconds {
                    value: 1_900_000_000,
                },
                finality,
                adapter_profile_hash: [16; 32],
            },
            adaptor_point_sec1: point(17)?,
            fee_limit: FeeLimitV1 {
                dom_max: 10,
                counterparty_max: 3,
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 100,
            },
            assurance_policy_hash: Some(policy.policy_hash()?),
            policy_version: 1,
            metadata: vec![],
        };
        let validated = policy.validate_for(&terms)?;
        let values = [
            policy.dom_principal_noms,
            validated.successful_change_noms(),
            validated.refund_payout_noms(),
            validated.compensation_payout_noms(),
        ];
        let commitments = values
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                BlindingFactor::from_bytes([index as u8 + 11; 32])
                    .map(|blind| *Commitment::commit(value, &blind).as_bytes())
            })
            .collect::<core::result::Result<Vec<_>, _>>()?;
        policy.claim_principal_commitment = commitments[0];
        policy.claim_change_commitment = commitments[1];
        policy.refund_recipient_commitment = commitments[2];
        policy.compensation_recipient_commitment = commitments[3];
        terms.assurance_policy_hash = Some(policy.policy_hash()?);
        let policy = policy.validate_for(&terms)?;
        let principal = make_offer(
            &terms,
            &policy,
            &chain,
            XmrGraphPayoutKindV22::ClaimPrincipal,
        )?;
        Ok(Self {
            terms,
            policy,
            chain,
            principal,
        })
    }

    fn input(&self) -> PrincipalInputsV25<'_> {
        PrincipalInputsV25 {
            terms: &self.terms,
            policy: &self.policy,
            chain: &self.chain,
            route_id: [90; 32],
            beneficiary: self.terms.dom_leg.beneficiary.0,
            participant_index: 1,
            direction: DirectionV1::Responder,
            offer: &self.principal,
        }
    }
}

fn make_offer(
    terms: &SettlementTermsV1,
    policy: &ValidatedXmrCompensationPolicyV11,
    chain: &TrustedChainIdV1,
    kind: XmrGraphPayoutKindV22,
) -> core::result::Result<XmrPolicyPayoutOfferV22, Box<dyn std::error::Error>> {
    let index = kind as u8 - 1;
    let (recipient, _, value) = kind.policy_payout(policy);
    let role = if recipient == policy.policy().dom_funder {
        DirectionV1::Initiator
    } else {
        DirectionV1::Responder
    };
    let blinding = BlindingFactor::from_bytes([index + 11; 32])?;
    let (proof, commitment) = dom_crypto::range_proof_prove_bytes(value, &blinding)?;
    let output = dom_consensus::TransactionOutput {
        commitment: Commitment::from_compressed_bytes(&commitment)?,
        proof,
    };
    let ownership = kind
        .success_kind()
        .map(|kind| {
            produce_xmr_payout_value_proof_v12(
                terms,
                policy,
                kind,
                role,
                chain,
                &SigningShareV1::from_be_bytes([index + 11; 32]).expect("test scalar"),
            )
        })
        .transpose()?;
    Ok(XmrPolicyPayoutOfferV22::new(
        terms, policy, kind, output, ownership, chain, role,
    )?)
}

#[test]
fn real_principal_proofs_and_common_public_record_are_stable_v25() -> TestResult {
    let fixture = Fixture::new()?;
    let first = verify_principal(&fixture.input())?;
    let second = verify_principal(&fixture.input())?;
    assert_eq!(first, second);
    assert!(first.starts_with(PRINCIPAL_DOMAIN));
    assert_ne!(
        digest(PAYOUT_COMMITMENT_DOMAIN, &[DOMAIN, &first])?,
        ZERO_DIGEST
    );
    assert_ne!(
        digest(PAYOUT_COMMITMENT_DOMAIN, &[DOMAIN, &first])?,
        digest(
            PAYOUT_COMMITMENT_DOMAIN,
            &[super::super::DOM_RECORD_DOMAIN, &first]
        )?
    );
    // A public equation record is not a provenance token or a wallet/F7 grant.
    // The real producer's tests cover local/peer/restart emission of the token.
    let mut another_route = fixture.input();
    another_route.route_id[0] ^= 1;
    assert_ne!(first, verify_principal(&another_route)?);
    Ok(())
}

#[test]
fn principal_recipient_roster_direction_chain_and_terms_transplants_fail_v25() -> TestResult {
    let fixture = Fixture::new()?;
    let mut input = fixture.input();
    input.route_id = [0; 32];
    assert!(verify_principal(&input).is_err());
    let mut input = fixture.input();
    input.beneficiary = [5; 32];
    assert!(verify_principal(&input).is_err());
    let mut input = fixture.input();
    input.participant_index = 0;
    assert!(verify_principal(&input).is_err());
    let mut input = fixture.input();
    input.direction = DirectionV1::Initiator;
    assert!(verify_principal(&input).is_err());
    let other_chain = TrustedChainIdV1::from_authenticated_genesis(
        0x000d_0012,
        &dom_core::Hash256::from_bytes([92; 32]),
    );
    let mut input = fixture.input();
    input.chain = &other_chain;
    assert!(verify_principal(&input).is_err());
    for change in 0..6 {
        let mut terms = fixture.terms.clone();
        match change {
            0 => terms.session_id.0[0] ^= 1,
            1 => terms.dom_leg.beneficiary.0[0] ^= 1,
            2 => terms.roster[0].0[0] ^= 1,
            3 => terms.dom_leg.amount += 1,
            4 => terms.counterparty_leg.mechanism = LockMechanism::CrossCurveConditionLock,
            _ => terms.dom_leg.deadline = TimelockSpec::BlockHeight { value: 101 },
        }
        let mut input = fixture.input();
        input.terms = &terms;
        assert!(
            verify_principal(&input).is_err(),
            "scope transplant {change}"
        );
    }
    Ok(())
}

#[test]
fn other_valid_policy_payouts_cannot_be_relabelled_as_principal_v25() -> TestResult {
    let fixture = Fixture::new()?;
    for kind in [
        XmrGraphPayoutKindV22::ClaimChange,
        XmrGraphPayoutKindV22::Refund,
        XmrGraphPayoutKindV22::Compensation,
    ] {
        let offer = make_offer(&fixture.terms, &fixture.policy, &fixture.chain, kind)?;
        let mut input = fixture.input();
        input.offer = &offer;
        assert!(verify_principal(&input).is_err());
    }
    Ok(())
}

#[test]
fn exact_public_principal_encoding_rejects_proof_and_capsule_mutations_v25() -> TestResult {
    let fixture = Fixture::new()?;
    let bytes = fixture.principal.to_bytes()?;
    let decode = |bytes: &[u8]| {
        XmrPolicyPayoutOfferV22::from_bytes(
            bytes,
            &fixture.terms,
            &fixture.policy,
            &fixture.chain,
            DirectionV1::Responder,
        )
    };
    for offset in [0, 8, 9, 41, 73, 105, 137, 186, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[offset] ^= 0x80;
        assert!(
            decode(&changed).is_err(),
            "mutated public proof offset {offset}"
        );
    }
    assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    let mut extended = bytes;
    extended.push(0);
    assert!(decode(&extended).is_err());
    let mut capsule_bytes = [0u8; 96];
    capsule_bytes[0..2].copy_from_slice(&1u16.to_le_bytes());
    capsule_bytes[14..16].copy_from_slice(&80u16.to_le_bytes());
    let capsule = RecoveryCapsule::from_bytes(&capsule_bytes)?;
    let old = fixture.principal.output();
    let (proof, commitment) = dom_crypto::range_proof_prove_bytes_with_extra_commit(
        fixture.policy.policy().dom_principal_noms,
        &BlindingFactor::from_bytes([11; 32])?,
        capsule.as_bytes(),
    )?;
    assert_eq!(old.commitment.as_bytes(), &commitment);
    let output = dom_consensus::TransactionOutput::with_recovery_capsule(
        old.commitment.clone(),
        proof,
        &capsule,
    )?;
    let ownership = fixture
        .principal
        .ownership()
        .ok_or("missing real principal proof")?;
    let ownership = XmrPayoutValueProofV11 {
        statement: ownership.statement.clone(),
        proof: ownership.proof.clone(),
    };
    assert!(XmrPolicyPayoutOfferV22::new(
        &fixture.terms,
        &fixture.policy,
        XmrGraphPayoutKindV22::ClaimPrincipal,
        output,
        Some(ownership),
        &fixture.chain,
        DirectionV1::Responder
    )
    .is_err());
    Ok(())
}

#[test]
fn changed_availability_requires_new_proof_not_reused_principal_authority_v25() -> TestResult {
    let fixture = Fixture::new()?;
    let original = verify_principal(&fixture.input())?;
    let mut policy = *fixture.policy.policy();
    policy
        .bounded_availability_v23
        .as_mut()
        .ok_or("missing negotiated availability")?
        .maximum_unavailability_blocks += 1;
    let mut terms = fixture.terms.clone();
    terms.assurance_policy_hash = Some(policy.policy_hash()?);
    let policy = policy.validate_for(&terms)?;
    let mut transplanted = fixture.input();
    transplanted.terms = &terms;
    transplanted.policy = &policy;
    assert!(verify_principal(&transplanted).is_err());
    let offer = make_offer(
        &terms,
        &policy,
        &fixture.chain,
        XmrGraphPayoutKindV22::ClaimPrincipal,
    )?;
    transplanted.offer = &offer;
    assert_ne!(verify_principal(&transplanted)?, original);
    Ok(())
}
