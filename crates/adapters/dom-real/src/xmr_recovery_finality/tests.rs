//! Native graph classification tests. Locators/tip are fixtures: these tests
//! exercise consensus and outcome classification, not RPC ancestry authentication.
use super::*;
use dom_adaptor::{
    canonical_template_v1, AdaptorSecret, BindingContextV1, PartialSignatureV1,
    ParticipantPublicNoncesV1, PurposeV1,
};
use dom_consensus::{Transaction, TransactionInput, TransactionKernel, TransactionOutput};
use dom_core::{Amount, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN};
use dom_crypto::{
    pedersen::{BlindingFactor, Commitment},
    range_proof_prove_bytes, schnorr_challenge, schnorr_sign, PartialSig, SecretKey,
};
use dom_scriptless_consensus::scriptless_kernel_message_digest_v1;
use dom_scriptless_crypto::{
    begin_refund_adaptor_round_v1, verify_xmr_recovery_graph_v11, RefundAdaptorRoundInputsV1,
    VerifiedRefundPreSignatureV1, XmrRecoveryGraphBindingV11, XmrRecoveryGraphRequestV11,
};
use dom_scriptless_primitives::{secret_scalar_mul_add_assign, secret_scalar_public_key};
use dom_serialization::DomSerialize;
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, String>;
const CHAIN: [u8; 32] = [41; 32];
const SESSION: [u8; 32] = [42; 32];
const TRANSCRIPT: [u8; 32] = [43; 32];

fn scalar(value: u8) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[31] = value;
    bytes
}
fn output(value: u64, blind: u8) -> TestResult<TransactionOutput> {
    let blind = BlindingFactor::from_bytes(scalar(blind)).map_err(|e| e.to_string())?;
    let (proof, commitment) = range_proof_prove_bytes(value, &blind).map_err(|e| e.to_string())?;
    Ok(TransactionOutput {
        commitment: Commitment::from_compressed_bytes(&commitment).map_err(|e| e.to_string())?,
        proof,
    })
}
fn transaction(
    input: &TransactionOutput,
    output: TransactionOutput,
    excess: u8,
    fee: u64,
    height: u64,
) -> TestResult<Transaction> {
    let blind = BlindingFactor::from_bytes(scalar(excess)).map_err(|e| e.to_string())?;
    Ok(Transaction {
        inputs: vec![TransactionInput {
            commitment: input.commitment.clone(),
        }],
        outputs: vec![output],
        offset: [0; 32],
        kernels: vec![TransactionKernel {
            features: if height == 0 {
                KERNEL_FEAT_PLAIN
            } else {
                KERNEL_FEAT_HEIGHT_LOCKED
            },
            fee: Amount::from_noms(fee).map_err(|e| e.to_string())?,
            lock_height: height,
            excess: Commitment::commit(0, &blind),
            excess_signature: [0; 65],
        }],
    })
}
fn signed(mut tx: Transaction, excess: u8) -> TestResult<Vec<u8>> {
    let key = SecretKey::from_bytes(&scalar(excess)).map_err(|e| e.to_string())?;
    let digest = scriptless_kernel_message_digest_v1(&tx.kernels[0]);
    tx.kernels[0].excess_signature = schnorr_sign(&key, digest.as_bytes(), &CHAIN)
        .map_err(|e| e.to_string())?
        .to_bytes();
    tx.to_bytes().map_err(|e| e.to_string())
}
fn refund_pre(tx: &Transaction) -> TestResult<VerifiedRefundPreSignatureV1> {
    // Test-only signing shares 4 + 6 equal the exact refund excess 10.
    // Both nonces per signer are distinct; no private test input enters the
    // production graph verifier or bypasses a native verification equation.
    let mut secrets = [
        (scalar(4), scalar(21), scalar(22)),
        (scalar(6), scalar(23), scalar(24)),
    ];
    secrets.sort_by_key(|(key, _, _)| {
        secret_scalar_public_key(key)
            .map(|point| point.to_compressed_bytes())
            .unwrap_or([0; 33])
    });
    let participants: Vec<_> = secrets
        .iter()
        .enumerate()
        .map(|(index, (key, r1, r2))| {
            Ok(ParticipantPublicNoncesV1 {
                participant_index: u16::try_from(index).map_err(|e| e.to_string())?,
                signing_key: secret_scalar_public_key(key).map_err(|e| e.to_string())?,
                first_nonce: secret_scalar_public_key(r1).map_err(|e| e.to_string())?,
                second_nonce: secret_scalar_public_key(r2).map_err(|e| e.to_string())?,
            })
        })
        .collect::<TestResult<_>>()?;
    let (_, template_hash) = canonical_template_v1(tx).map_err(|e| e.to_string())?;
    let key = secret_scalar_public_key(&scalar(10)).map_err(|e| e.to_string())?;
    let point = secret_scalar_public_key(&scalar(7)).map_err(|e| e.to_string())?;
    let message = *scriptless_kernel_message_digest_v1(&tx.kernels[0]).as_bytes();
    let round = begin_refund_adaptor_round_v1(&RefundAdaptorRoundInputsV1 {
        binding_context: BindingContextV1 {
            chain_id: CHAIN,
            session_id: SESSION,
            purpose: PurposeV1::RefundAdaptor,
            template_hash,
        },
        participants: &participants,
        refund_adaptor_point: point,
        aggregate_signing_key: key.clone(),
        transcript_hash: TRANSCRIPT,
        kernel_message_digest: message,
    })
    .map_err(|e| e.to_string())?;
    let challenge = schnorr_challenge(
        &round.aggregate_nonce_hat().to_compressed_bytes(),
        &key,
        &CHAIN,
        &message,
    );
    let mut partials = Vec::new();
    for (index, (key, r1, r2)) in secrets.iter().enumerate() {
        let mut accumulator = Zeroizing::new(*r1);
        secret_scalar_mul_add_assign(&mut accumulator, r2, round.binding_factor())
            .map_err(|e| e.to_string())?;
        secret_scalar_mul_add_assign(&mut accumulator, key, challenge.as_bytes())
            .map_err(|e| e.to_string())?;
        partials.push(PartialSignatureV1::new(
            PurposeV1::RefundAdaptor,
            participants[index].participant_index,
            template_hash,
            PartialSig::from_bytes(accumulator.as_ref()).map_err(|e| e.to_string())?,
        ));
    }
    round
        .aggregate_pre_signature_v1(&partials)
        .map_err(|e| e.to_string())
}
struct Fixture {
    binding: XmrRecoveryGraphBindingV11,
    funding: Transaction,
    claim: Transaction,
    cancel: Vec<u8>,
    refund: Transaction,
    punish: Vec<u8>,
}
impl Fixture {
    fn new() -> TestResult<Self> {
        let source = output(10_100, 5)?;
        let c = output(10_000, 10)?;
        let d = output(9_900, 20)?;
        let refund_output = output(9_800, 30)?;
        let punish_output = output(9_750, 40)?;
        let binding = XmrRecoveryGraphBindingV11 {
            chain_id: CHAIN,
            session_id: SESSION,
            terms_hash: [44; 32],
            funding_commitment: *c.commitment.as_bytes(),
            cancelled_commitment: *d.commitment.as_bytes(),
            refund_recipient_commitment: *refund_output.commitment.as_bytes(),
            punish_recipient_commitment: *punish_output.commitment.as_bytes(),
            claim_adaptor_point: secret_scalar_public_key(&scalar(9))
                .map_err(|e| e.to_string())?
                .to_compressed_bytes(),
            refund_adaptor_point: secret_scalar_public_key(&scalar(7))
                .map_err(|e| e.to_string())?
                .to_compressed_bytes(),
            cancel_height: 100,
            punish_height: 200,
            reveal_safety_blocks: 10,
            cancel_fee: 100,
            refund_fee: 100,
            punish_fee: 150,
        };
        Ok(Self {
            binding,
            funding: transaction(&source, c.clone(), 5, 100, 0)?,
            claim: transaction(&c, output(9_900, 25)?, 15, 100, 0)?,
            cancel: signed(transaction(&c, d.clone(), 10, 100, 100)?, 10)?,
            refund: transaction(&d, refund_output, 10, 100, 100)?,
            punish: signed(transaction(&d, punish_output, 20, 150, 200)?, 20)?,
        })
    }
    fn request(&self) -> TestResult<XmrRecoveryGraphRequestV11<'_>> {
        Ok(XmrRecoveryGraphRequestV11 {
            binding: self.binding,
            funding_template: &self.funding,
            claim_template: &self.claim,
            cancel_bytes: &self.cancel,
            refund_template: &self.refund,
            refund_pre_signature: refund_pre(&self.refund)?,
            punish_bytes: &self.punish,
        })
    }
}

fn located(bytes: Vec<u8>, height: u64) -> TestResult<CanonicalTransactionEvidenceV1> {
    let mut hash = [81; 32];
    hash[..8].copy_from_slice(&height.to_be_bytes());
    CanonicalTransactionEvidenceV1::from_canonical_bytes_at(height, hash, 0, bytes)
        .map_err(|e| e.to_string())
}
fn snapshot(tip_height: u64) -> TestResult<(CursorStateV1, ObservedDomIdentityV1)> {
    let mut history = Vec::new();
    for height in tip_height.saturating_sub(5)..=tip_height {
        let mut hash = [81; 32];
        hash[..8].copy_from_slice(&height.to_be_bytes());
        history.push((height, hash));
    }
    let tip_hash = history.last().ok_or("missing test tip")?.1;
    Ok((
        CursorStateV1 {
            next_height: tip_height + 1,
            history,
        },
        ObservedDomIdentityV1 {
            network: "test-fixture".to_owned(),
            network_magic: 1,
            chain_id: CHAIN,
            genesis_hash: [61; 32],
            protocol_version: 1,
            range_proof_serialization_version: 1,
            coinbase_maturity: 1,
            tip_height,
            tip_hash,
        },
    ))
}
fn graph_trace(
    fixture: &Fixture,
    graph: &VerifiedXmrRecoveryGraphV11,
    cancel: bool,
    terminal: Option<(Vec<u8>, u64)>,
) -> TestResult<GraphTrace> {
    let mut trace = GraphTrace::default();
    trace
        .observe(graph, &located(signed(fixture.funding.clone(), 5)?, 80)?)
        .map_err(|e| e.to_string())?;
    if cancel {
        trace
            .observe(graph, &located(fixture.cancel.clone(), 100)?)
            .map_err(|e| e.to_string())?;
    }
    if let Some((bytes, height)) = terminal {
        trace
            .observe(graph, &located(bytes, height)?)
            .map_err(|e| e.to_string())?;
    }
    Ok(trace)
}

#[test]
fn native_c_collateral_and_d_cancellation_are_distinct_from_terminal_outcomes() -> TestResult {
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let (state, tip) = snapshot(110)?;
    let collateral = classify_graph(
        &graph,
        graph_trace(&fixture, &graph, false, None)?,
        &state,
        &tip,
        2,
        5,
    )
    .map_err(|e| e.to_string())?;
    let VerifiedDomXmrRecoveryStateV11::CollateralReady(collateral) = collateral else {
        return Err("unexpected collateral result".into());
    };
    assert_eq!(collateral.finality().cancel_tx_hash(), None);
    assert_eq!(collateral.finality().graph_digest(), *graph.graph_digest());
    let cancelled = classify_graph(
        &graph,
        graph_trace(&fixture, &graph, true, None)?,
        &state,
        &tip,
        2,
        5,
    )
    .map_err(|e| e.to_string())?;
    let VerifiedDomXmrRecoveryStateV11::Cancelled(cancelled) = cancelled else {
        return Err("unexpected cancellation result".into());
    };
    assert_eq!(cancelled.finality().block_height(), 100);
    assert_eq!(
        cancelled.finality().cancel_tx_hash(),
        Some(cancelled.finality().transaction_hash())
    );
    Ok(())
}

#[test]
fn native_refund_reveals_only_u_while_plain_punish_is_dom_compensation() -> TestResult {
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let witness = AdaptorSecret::from_be_bytes(scalar(7)).map_err(|e| e.to_string())?;
    let private = graph
        .complete_private_refund(&witness)
        .map_err(|e| e.to_string())?;
    let bytes = private.with_secret_bytes(|bytes| bytes.to_vec());
    let (state, tip) = snapshot(210)?;
    let refunded = classify_graph(
        &graph,
        graph_trace(&fixture, &graph, true, Some((bytes, 120)))?,
        &state,
        &tip,
        2,
        5,
    )
    .map_err(|e| e.to_string())?;
    let VerifiedDomXmrRecoveryStateV11::Refunded(refunded) = refunded else {
        return Err("unexpected refund result".into());
    };
    refunded.expose(|u| assert_eq!(*u, scalar(7)));
    assert_eq!(refunded.finality().terms_hash(), fixture.binding.terms_hash);
    assert_eq!(
        refunded.finality().transaction_hash(),
        *private.transaction_hash()
    );
    let compensated = classify_graph(
        &graph,
        graph_trace(&fixture, &graph, true, Some((fixture.punish.clone(), 200)))?,
        &state,
        &tip,
        2,
        5,
    )
    .map_err(|e| e.to_string())?;
    let VerifiedDomXmrRecoveryStateV11::Compensated(compensated) = compensated else {
        return Err("punish was mislabeled as XMR refund".into());
    };
    assert_eq!(compensated.finality().graph_digest(), *graph.graph_digest());
    assert_eq!(compensated.finality().block_height(), 200);
    assert_ne!(
        compensated.finality().transaction_hash(),
        refunded.finality().transaction_hash()
    );
    Ok(())
}

#[test]
fn early_punish_duplicate_spends_and_orphan_d_are_hard_refusals() -> TestResult {
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let (state, tip) = snapshot(210)?;
    let mut trace = graph_trace(&fixture, &graph, true, None)?;
    assert!(matches!(
        trace.observe(&graph, &located(fixture.punish.clone(), 199)?),
        Err(RealDomError::InvalidEvidence)
    ));
    let mut trace = graph_trace(&fixture, &graph, true, Some((fixture.punish.clone(), 200)))?;
    assert!(matches!(
        trace.observe(&graph, &located(fixture.punish.clone(), 201)?),
        Err(RealDomError::InvalidEvidence)
    ));
    let orphan = graph_trace(&fixture, &graph, false, Some((fixture.punish.clone(), 200)))?;
    assert!(matches!(
        classify_graph(&graph, orphan, &state, &tip, 2, 5),
        Err(RealDomError::InvalidEvidence)
    ));
    Ok(())
}

#[test]
fn normal_claim_is_no_refund_and_immature_cancellation_stays_unavailable() -> TestResult {
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let (state, tip) = snapshot(100)?;
    let claimed = graph_trace(
        &fixture,
        &graph,
        false,
        Some((signed(fixture.claim.clone(), 15)?, 90)),
    )?;
    assert!(matches!(
        classify_graph(&graph, claimed, &state, &tip, 2, 5),
        Err(RealDomError::EvidenceNotFound)
    ));
    let cancelled = graph_trace(&fixture, &graph, true, None)?;
    assert!(matches!(
        classify_graph(&graph, cancelled, &state, &tip, 2, 5),
        Err(RealDomError::InsufficientConfirmations)
    ));
    Ok(())
}

#[test]
fn changing_tip_is_retryable_but_substituted_chain_is_conflict() -> TestResult {
    let (_, original) = snapshot(210)?;
    require_same_snapshot(&original, &original).map_err(|e| e.to_string())?;
    let (_, later) = snapshot(211)?;
    assert!(matches!(
        require_same_snapshot(&original, &later),
        Err(RealDomError::Chain(
            ChainAdapterError::TemporarilyUnavailable
        ))
    ));
    let mut foreign = original.clone();
    foreign.chain_id[0] ^= 1;
    assert!(matches!(
        require_same_snapshot(&original, &foreign),
        Err(RealDomError::InvalidEvidence)
    ));
    Ok(())
}
