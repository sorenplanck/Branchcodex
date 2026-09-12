//! Native cryptographic transaction tests, not daemon or live-chain evidence.
use dom_adaptor::{
    canonical_template_v1, AdaptorSecret, BindingContextV1, PartialSignatureV1,
    ParticipantPublicNoncesV1, PurposeV1,
};
use dom_consensus::{
    validate_transaction, Transaction, TransactionInput, TransactionKernel, TransactionOutput,
    ValidationContext,
};
use dom_core::{Amount, BlockHeight, Timestamp, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN};
use dom_crypto::{
    pedersen::{BlindingFactor, Commitment},
    range_proof_prove_bytes, schnorr_challenge, schnorr_sign, PartialSig, SecretKey,
};
use dom_scriptless_consensus::scriptless_kernel_message_digest_v1;
use dom_scriptless_crypto::{
    begin_refund_adaptor_round_v1, verify_xmr_recovery_graph_v11, RefundAdaptorRoundInputsV1,
    VerifiedRefundPreSignatureV1, XmrRecoveryGraphBindingV11, XmrRecoveryGraphErrorV11,
    XmrRecoveryGraphRequestV11,
};
use dom_scriptless_primitives::{secret_scalar_mul_add_assign, secret_scalar_public_key};
use dom_serialization::{DomDeserialize, DomSerialize};
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

fn ordinary_v12(
    fixture: &Fixture,
    kind: dom_scriptless_crypto::XmrOrdinaryRecoveryKindV12,
) -> TestResult<(
    dom_scriptless_crypto::XmrOrdinaryRecoveryRoundV12,
    Vec<PartialSignatureV1>,
)> {
    ordinary_with_policy(fixture, kind, None)
}

fn ordinary_with_policy(
    fixture: &Fixture,
    kind: dom_scriptless_crypto::XmrOrdinaryRecoveryKindV12,
    policy: Option<&xmr_compensation_policy::ValidatedXmrCompensationPolicyV11>,
) -> TestResult<(
    dom_scriptless_crypto::XmrOrdinaryRecoveryRoundV12,
    Vec<PartialSignatureV1>,
)> {
    use dom_scriptless_crypto::{XmrOrdinaryRecoveryKindV12, XmrOrdinaryRecoveryRoundV12};
    let (bytes, a, b, nonce_base) = match kind {
        XmrOrdinaryRecoveryKindV12::Cancel => (&fixture.cancel, 4, 6, 31),
        XmrOrdinaryRecoveryKindV12::Compensation => (&fixture.punish, 8, 12, 41),
    };
    let mut transaction = Transaction::from_bytes(bytes).map_err(|error| error.to_string())?;
    transaction.kernels[0].excess_signature = [0; 65];
    let mut secrets = [
        (scalar(a), scalar(nonce_base), scalar(nonce_base + 1)),
        (scalar(b), scalar(nonce_base + 2), scalar(nonce_base + 3)),
    ];
    secrets.sort_by_key(|(key, _, _)| {
        secret_scalar_public_key(key)
            .map(|point| point.to_compressed_bytes())
            .unwrap_or([0; 33])
    });
    let participants = secrets
        .iter()
        .enumerate()
        .map(|(index, (key, first, second))| {
            Ok(ParticipantPublicNoncesV1 {
                participant_index: u16::try_from(index).map_err(|error| error.to_string())?,
                signing_key: secret_scalar_public_key(key).map_err(|error| error.to_string())?,
                first_nonce: secret_scalar_public_key(first).map_err(|error| error.to_string())?,
                second_nonce: secret_scalar_public_key(second)
                    .map_err(|error| error.to_string())?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    let round = match policy {
        Some(policy) => XmrOrdinaryRecoveryRoundV12::begin_bounded_compensation_v23(
            fixture.binding,
            policy,
            &transaction,
            &participants,
        ),
        None => {
            XmrOrdinaryRecoveryRoundV12::begin(fixture.binding, kind, &transaction, &participants)
        }
    }
    .map_err(|error| error.to_string())?;
    let factor = dom_adaptor::binding_factor_v1(round.context(), &participants, None)
        .map_err(|error| error.to_string())?;
    let nonces = participants
        .iter()
        .map(|participant| {
            factor
                .bind_public_nonces(&participant.first_nonce, &participant.second_nonce)
                .map_err(|error| error.to_string())
        })
        .collect::<TestResult<Vec<_>>>()?;
    let aggregate_nonce =
        dom_adaptor::aggregate_public_nonces_v1(&nonces).map_err(|error| error.to_string())?;
    let key = secret_scalar_public_key(&scalar(a + b)).map_err(|error| error.to_string())?;
    let message = scriptless_kernel_message_digest_v1(&transaction.kernels[0]);
    let challenge = schnorr_challenge(
        &aggregate_nonce.to_compressed_bytes(),
        &key,
        &CHAIN,
        message.as_bytes(),
    );
    let mut partials = Vec::new();
    for (index, (key, first, second)) in secrets.iter().enumerate() {
        let mut accumulator = Zeroizing::new(*first);
        secret_scalar_mul_add_assign(&mut accumulator, second, &factor.to_be_bytes())
            .map_err(|error| error.to_string())?;
        secret_scalar_mul_add_assign(&mut accumulator, key, challenge.as_bytes())
            .map_err(|error| error.to_string())?;
        partials.push(PartialSignatureV1::new(
            PurposeV1::Refund,
            participants[index].participant_index,
            round.context().template_hash,
            PartialSig::from_bytes(accumulator.as_ref()).map_err(|error| error.to_string())?,
        ));
    }
    Ok((round, partials))
}

#[test]
fn v13_cancel_still_signs_but_unconditional_compensation_cannot_be_produced() -> TestResult {
    use dom_scriptless_crypto::{
        require_safe_ordinary_recovery_kind_v13, XmrOrdinaryRecoveryErrorV12,
        XmrOrdinaryRecoveryKindV12, XmrOrdinaryRecoveryRoundV12,
    };
    let fixture = Fixture::new()?;
    let (round, partials) = ordinary_v12(&fixture, XmrOrdinaryRecoveryKindV12::Cancel)?;
    let cancel = round.complete(&partials).map_err(|e| e.to_string())?;
    let transaction =
        Transaction::from_bytes(cancel.transaction_bytes()).map_err(|e| e.to_string())?;
    let context = |height| ValidationContext {
        current_height: BlockHeight(height),
        chain_id: CHAIN,
        now: Timestamp(0),
    };
    assert!(validate_transaction(&transaction, &context(99)).is_err());
    validate_transaction(&transaction, &context(100)).map_err(|e| e.to_string())?;
    assert_eq!(
        require_safe_ordinary_recovery_kind_v13(XmrOrdinaryRecoveryKindV12::Compensation),
        Err(XmrOrdinaryRecoveryErrorV12::FundingConditionUnavailable)
    );
    // The constructor refuses before even processing caller-supplied nonces.
    assert_eq!(
        XmrOrdinaryRecoveryRoundV12::begin(
            fixture.binding,
            XmrOrdinaryRecoveryKindV12::Compensation,
            &transaction,
            &[]
        )
        .err(),
        Some(XmrOrdinaryRecoveryErrorV12::FundingConditionUnavailable)
    );
    Ok(())
}

#[test]
fn v22_retired_consensus_path_refuses_compensation_even_with_a_funding_marker() -> TestResult {
    use dom_scriptless_crypto::{
        require_ordinary_recovery_kind_admitted_v22, XmrCompensationFundingWitnessV22,
        XmrOrdinaryRecoveryErrorV12, XmrOrdinaryRecoveryKindV12, XmrOrdinaryRecoveryRoundV12,
    };
    let fixture = Fixture::new()?;
    let graph =
        verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|error| error.to_string())?;
    assert!(graph.require_conditional_compensation_v22().is_err());
    let mut transaction =
        Transaction::from_bytes(&fixture.punish).map_err(|error| error.to_string())?;
    transaction.kernels[0].excess_signature = [0; 65];
    let marker = XmrCompensationFundingWitnessV22::from_authorized_observation_v22(
        fixture.binding.chain_id,
        fixture.binding.session_id,
        fixture.binding.terms_hash,
        [99; 32],
    )
    .map_err(|error| error.to_string())?;
    for witness in [None, Some(&marker)] {
        assert_eq!(
            require_ordinary_recovery_kind_admitted_v22(
                XmrOrdinaryRecoveryKindV12::Compensation,
                &fixture.binding,
                &transaction,
                witness,
            ),
            Err(XmrOrdinaryRecoveryErrorV12::FundingConditionUnavailable),
        );
        // Refusal precedes nonce processing, even through the former V22 API.
        assert_eq!(
            XmrOrdinaryRecoveryRoundV12::begin_with_funding_v22(
                fixture.binding,
                XmrOrdinaryRecoveryKindV12::Compensation,
                &transaction,
                &[],
                witness,
            )
            .err(),
            Some(XmrOrdinaryRecoveryErrorV12::FundingConditionUnavailable),
        );
    }
    Ok(())
}

#[test]
fn v13_legacy_signed_compensation_remains_spendable_without_xmr_and_must_not_be_newly_armed(
) -> TestResult {
    let fixture = Fixture::new()?;
    let transaction = Transaction::from_bytes(&fixture.punish).map_err(|e| e.to_string())?;
    // No Monero funding, RPC, sidecar, daemon or local eligibility database is
    // involved. Given the legacy D input, ordinary consensus checks accept it.
    let context = ValidationContext {
        current_height: BlockHeight(200),
        chain_id: CHAIN,
        now: Timestamp(0),
    };
    validate_transaction(&transaction, &context).map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn v13_cancel_refuses_adaptor_partials_and_reused_native_nonces() -> TestResult {
    use dom_scriptless_crypto::{XmrOrdinaryRecoveryErrorV12, XmrOrdinaryRecoveryKindV12};
    let fixture = Fixture::new()?;
    let (round, partials) = ordinary_v12(&fixture, XmrOrdinaryRecoveryKindV12::Cancel)?;
    let mut swapped = partials[0].to_bytes();
    swapped[0] = PurposeV1::RefundAdaptor.to_byte();
    let altered = vec![
        PartialSignatureV1::from_bytes(&swapped).map_err(|error| error.to_string())?,
        PartialSignatureV1::from_bytes(&partials[1].to_bytes())
            .map_err(|error| error.to_string())?,
    ];
    assert_eq!(
        round.complete(&altered).err(),
        Some(XmrOrdinaryRecoveryErrorV12::Signature)
    );
    let (round, partials) = ordinary_v12(&fixture, XmrOrdinaryRecoveryKindV12::Cancel)?;
    let complete = round
        .complete(&partials)
        .map_err(|error| error.to_string())?;
    assert_eq!(
        dom_scriptless_crypto::require_distinct_xmr_recovery_nonces_v12(&[
            complete.public_nonces(),
            complete.public_nonces()
        ]),
        Err(XmrOrdinaryRecoveryErrorV12::NonceReuse)
    );
    let mut other_binding = fixture.binding;
    other_binding.session_id[0] ^= 1;
    let other = dom_scriptless_crypto::xmr_ordinary_recovery_session_v12(
        &other_binding,
        XmrOrdinaryRecoveryKindV12::Cancel,
        complete.context().template_hash,
    );
    assert_ne!(other, complete.context().session_id);
    Ok(())
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

#[test]
fn v11_native_graph_and_private_adaptor_refund_pass_consensus() -> TestResult {
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    assert_eq!(graph.cancel_bytes(), &fixture.cancel);
    assert_eq!(graph.punish_bytes(), &fixture.punish);
    let secret = AdaptorSecret::from_be_bytes(scalar(7)).map_err(|e| e.to_string())?;
    let private = graph
        .complete_private_refund(&secret)
        .map_err(|e| e.to_string())?;
    assert_eq!(private.graph_digest(), graph.graph_digest());
    private.with_secret_bytes(|bytes| -> TestResult {
        let transaction = Transaction::from_bytes(bytes).map_err(|e| e.to_string())?;
        let context = |height| ValidationContext {
            current_height: BlockHeight(height),
            chain_id: CHAIN,
            now: Timestamp(0),
        };
        validate_transaction(&transaction, &context(100)).map_err(|e| e.to_string())?;
        assert!(validate_transaction(&transaction, &context(99)).is_err());
        let pre = refund_pre(&fixture.refund)?;
        let recovered = pre
            .extract(&transaction.kernels[0].excess_signature)
            .map_err(|e| e.to_string())?;
        assert_eq!(*recovered, scalar(7));
        Ok(())
    })?;
    let wrong = AdaptorSecret::from_be_bytes(scalar(8)).map_err(|e| e.to_string())?;
    assert!(graph.complete_private_refund(&wrong).is_err());
    Ok(())
}

#[test]
fn v22_local_claim_deadline_does_not_expire_a_signed_claim() -> TestResult {
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    // Test-only ordinary signature isolates the native transaction deadline.
    // This is not evidence of claim-adaptor admission or a daemon claim.
    let claim =
        Transaction::from_bytes(&signed(fixture.claim.clone(), 15)?).map_err(|e| e.to_string())?;
    let cancel = Transaction::from_bytes(&fixture.cancel).map_err(|e| e.to_string())?;
    assert_eq!(claim.inputs[0].commitment, cancel.inputs[0].commitment);
    for height in [100, 200, 201] {
        assert!(graph.require_claim_window(height).is_err());
        let context = ValidationContext {
            current_height: BlockHeight(height),
            chain_id: CHAIN,
            now: Timestamp(0),
        };
        validate_transaction(&claim, &context).map_err(|e| e.to_string())?;
        validate_transaction(&cancel, &context).map_err(|e| e.to_string())?;
    }
    // Individual validity is not simultaneous inclusion: both spend C.
    // Cancellation must be confirmed/revalidated, not inferred from the clock.
    Ok(())
}

#[test]
fn v22_refund_witness_is_extractable_after_local_deadline_without_confirmation() -> TestResult {
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let secret = AdaptorSecret::from_be_bytes(scalar(7)).map_err(|e| e.to_string())?;
    let private = graph
        .complete_private_refund(&secret)
        .map_err(|e| e.to_string())?;
    let punish = Transaction::from_bytes(&fixture.punish).map_err(|e| e.to_string())?;
    private.with_secret_bytes(|bytes| -> TestResult {
        let refund = Transaction::from_bytes(bytes).map_err(|e| e.to_string())?;
        assert_eq!(refund.inputs[0].commitment, punish.inputs[0].commitment);
        let context = |height| ValidationContext {
            current_height: BlockHeight(height),
            chain_id: CHAIN,
            now: Timestamp(0),
        };
        assert!(validate_transaction(&punish, &context(199)).is_err());
        for height in [200, 201] {
            assert!(graph.require_refund_window(height).is_err());
            validate_transaction(&refund, &context(height)).map_err(|e| e.to_string())?;
            validate_transaction(&punish, &context(height)).map_err(|e| e.to_string())?;
        }
        // Extraction consumes a signature alone: no inclusion/finality proof.
        // A losing broadcast may reveal U even if punish is the confirmed spend.
        let recovered = refund_pre(&fixture.refund)?
            .extract(&refund.kernels[0].excess_signature)
            .map_err(|e| e.to_string())?;
        assert_eq!(*recovered, scalar(7));
        Ok(())
    })?;
    // This tests native transaction validity and witness exposure, not a live
    // mempool race, UTXO inclusion or an authorization to broadcast either path.
    assert!(graph.require_conditional_compensation_v22().is_err());
    Ok(())
}

#[test]
fn v11_encrypted_recovery_archive_reverifies_native_graph_and_private_refund() -> TestResult {
    use dom_scriptless_crypto::{
        open_xmr_recovery_archive_v11, seal_xmr_recovery_archive_v11, XmrRecoverySealKeyV11,
    };
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let witness = AdaptorSecret::from_be_bytes(scalar(7)).map_err(|e| e.to_string())?;
    let private = graph
        .complete_private_refund(&witness)
        .map_err(|e| e.to_string())?;
    let key =
        XmrRecoverySealKeyV11::from_bytes(Zeroizing::new([91; 32])).map_err(|e| e.to_string())?;
    let envelope = seal_xmr_recovery_archive_v11(&graph, [92; 32], &key, Some(&private))
        .map_err(|e| e.to_string())?;
    let other_nonce = seal_xmr_recovery_archive_v11(&graph, [92; 32], &key, Some(&private))
        .map_err(|e| e.to_string())?;
    assert_ne!(envelope, other_nonce);
    private.with_secret_bytes(|bytes| {
        assert!(!envelope.windows(bytes.len()).any(|window| window == bytes));
    });
    let opened = open_xmr_recovery_archive_v11(
        fixture.binding,
        *graph.graph_digest(),
        [92; 32],
        &key,
        &envelope,
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(
        opened.shape(),
        dom_scriptless_crypto::XmrRecoveryArchiveShapeV11::WithPrivateRefund
    );
    assert_eq!(opened.graph().graph_digest(), graph.graph_digest());
    assert_eq!(opened.graph().cancel_bytes(), graph.cancel_bytes());
    assert_eq!(opened.graph().punish_bytes(), graph.punish_bytes());
    opened.with_private_refund(|restored| -> TestResult {
        let restored = restored.ok_or("private refund missing")?;
        assert_eq!(restored.transaction_hash(), private.transaction_hash());
        restored.with_secret_bytes(|bytes| {
            private.with_secret_bytes(|expected| {
                assert_eq!(bytes, expected);
            })
        });
        Ok(())
    })?;
    Ok(())
}

#[test]
fn v11_recovery_archive_refuses_transplant_corruption_and_wrong_key() -> TestResult {
    use dom_scriptless_crypto::{
        open_xmr_recovery_archive_v11, seal_xmr_recovery_archive_v11, XmrRecoveryArchiveErrorV11,
        XmrRecoverySealKeyV11,
    };
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let key =
        XmrRecoverySealKeyV11::from_bytes(Zeroizing::new([91; 32])).map_err(|e| e.to_string())?;
    let envelope =
        seal_xmr_recovery_archive_v11(&graph, [92; 32], &key, None).map_err(|e| e.to_string())?;
    let wrong_key =
        XmrRecoverySealKeyV11::from_bytes(Zeroizing::new([90; 32])).map_err(|e| e.to_string())?;
    assert_eq!(
        open_xmr_recovery_archive_v11(
            fixture.binding,
            *graph.graph_digest(),
            [92; 32],
            &wrong_key,
            &envelope
        )
        .err(),
        Some(XmrRecoveryArchiveErrorV11::AuthenticationFailed)
    );
    assert_eq!(
        open_xmr_recovery_archive_v11(
            fixture.binding,
            *graph.graph_digest(),
            [93; 32],
            &key,
            &envelope
        )
        .err(),
        Some(XmrRecoveryArchiveErrorV11::AuthenticationFailed)
    );
    for field in 0..3 {
        let mut binding = fixture.binding;
        match field {
            0 => binding.chain_id[0] ^= 1,
            1 => binding.session_id[0] ^= 1,
            _ => binding.terms_hash[0] ^= 1,
        };
        assert_eq!(
            open_xmr_recovery_archive_v11(
                binding,
                *graph.graph_digest(),
                [92; 32],
                &key,
                &envelope
            )
            .err(),
            Some(XmrRecoveryArchiveErrorV11::AuthenticationFailed)
        );
    }
    // Temporal fields are bound by native graph digest, even though they are
    // not independently repeated in the AEAD header.
    let mut wrong_height = fixture.binding;
    wrong_height.cancel_height += 1;
    assert_eq!(
        open_xmr_recovery_archive_v11(
            wrong_height,
            *graph.graph_digest(),
            [92; 32],
            &key,
            &envelope
        )
        .err(),
        Some(XmrRecoveryArchiveErrorV11::InvalidGraph)
    );
    for index in [8, 31, 36, envelope.len() / 2, envelope.len() - 1] {
        let mut changed = envelope.clone();
        changed[index] ^= 1;
        assert!(open_xmr_recovery_archive_v11(
            fixture.binding,
            *graph.graph_digest(),
            [92; 32],
            &key,
            &changed
        )
        .is_err());
    }
    for length in [0, 7, 8, 31, 35, 36, envelope.len() - 1] {
        assert!(open_xmr_recovery_archive_v11(
            fixture.binding,
            *graph.graph_digest(),
            [92; 32],
            &key,
            &envelope[..length]
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn v11_counterparty_recovery_archive_contains_no_completed_refund() -> TestResult {
    use dom_scriptless_crypto::{
        open_xmr_recovery_archive_v11, seal_xmr_recovery_archive_v11, XmrRecoverySealKeyV11,
    };
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let key =
        XmrRecoverySealKeyV11::from_bytes(Zeroizing::new([91; 32])).map_err(|e| e.to_string())?;
    let envelope =
        seal_xmr_recovery_archive_v11(&graph, [92; 32], &key, None).map_err(|e| e.to_string())?;
    let opened = open_xmr_recovery_archive_v11(
        fixture.binding,
        *graph.graph_digest(),
        [92; 32],
        &key,
        &envelope,
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(
        opened.shape(),
        dom_scriptless_crypto::XmrRecoveryArchiveShapeV11::PublicGraphOnly
    );
    opened.with_private_refund(|private| assert!(private.is_none()));
    Ok(())
}

#[test]
fn v11_recovery_never_accepts_wrong_graph_fees_or_signed_bytes() -> TestResult {
    let fixture = Fixture::new()?;
    let mut request = fixture.request()?;
    request.binding.cancelled_commitment = request.binding.funding_commitment;
    assert!(matches!(
        verify_xmr_recovery_graph_v11(request),
        Err(XmrRecoveryGraphErrorV11::InvalidBinding)
    ));
    let mut request = fixture.request()?;
    request.binding.punish_fee += 1;
    assert!(matches!(
        verify_xmr_recovery_graph_v11(request),
        Err(XmrRecoveryGraphErrorV11::FeeMismatch)
    ));
    let mut request = fixture.request()?;
    request.binding.refund_adaptor_point = request.binding.claim_adaptor_point;
    assert!(matches!(
        verify_xmr_recovery_graph_v11(request),
        Err(XmrRecoveryGraphErrorV11::InvalidBinding)
    ));
    let mut request = fixture.request()?;
    request.binding.refund_adaptor_point = secret_scalar_public_key(&scalar(8))
        .map_err(|e| e.to_string())?
        .to_compressed_bytes();
    assert!(matches!(
        verify_xmr_recovery_graph_v11(request),
        Err(XmrRecoveryGraphErrorV11::RefundPreSignatureMismatch)
    ));
    let mut bad_cancel = fixture.cancel.clone();
    bad_cancel.push(0);
    let mut request = fixture.request()?;
    request.cancel_bytes = &bad_cancel;
    assert!(verify_xmr_recovery_graph_v11(request).is_err());
    let mut request = fixture.request()?;
    request.punish_bytes = &fixture.cancel;
    assert!(verify_xmr_recovery_graph_v11(request).is_err());
    let mut request = fixture.request()?;
    request.binding.chain_id[0] ^= 1;
    assert!(verify_xmr_recovery_graph_v11(request).is_err());
    let mut request = fixture.request()?;
    request.binding.session_id[0] ^= 1;
    assert!(matches!(
        verify_xmr_recovery_graph_v11(request),
        Err(XmrRecoveryGraphErrorV11::RefundPreSignatureMismatch)
    ));
    Ok(())
}

#[test]
fn v11_adaptor_reveal_windows_are_strict_and_overflow_safe() -> TestResult {
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    graph.require_claim_window(89).map_err(|e| e.to_string())?;
    assert_eq!(
        graph.require_claim_window(90),
        Err(XmrRecoveryGraphErrorV11::RevealWindowClosed)
    );
    assert!(graph.require_refund_window(99).is_err());
    graph
        .require_refund_window(100)
        .map_err(|e| e.to_string())?;
    graph
        .require_refund_window(189)
        .map_err(|e| e.to_string())?;
    assert!(graph.require_refund_window(190).is_err());
    assert!(graph.require_refund_window(u64::MAX).is_err());
    let mut request = fixture.request()?;
    request.binding.cancel_height = u64::MAX;
    assert!(verify_xmr_recovery_graph_v11(request).is_err());
    Ok(())
}

#[path = "support/xmr_compensation_terms_v23.rs"]
mod bounded_terms;

#[test]
fn v23_bounded_compensation_uses_native_partials_and_a_distinct_session() -> TestResult {
    use dom_scriptless_crypto::{
        xmr_compensation_session_v23, xmr_ordinary_recovery_session_v12, XmrOrdinaryRecoveryKindV12,
    };
    let mut fixture = Fixture::new()?;
    let policy = bounded_terms::policy_for(&mut fixture, true)?;
    assert_eq!(policy.collateral_noms(), 10_000);
    assert_eq!(policy.compensation_payout_noms(), 9_750);
    let kind = XmrOrdinaryRecoveryKindV12::Compensation;
    let (round, partials) = ordinary_with_policy(&fixture, kind, Some(&policy))?;
    assert_eq!(
        round.context().session_id,
        xmr_compensation_session_v23(
            &fixture.binding,
            round.context().template_hash,
            policy.policy().policy_hash().map_err(|e| e.to_string())?,
        )
    );
    assert_ne!(
        round.context().session_id,
        xmr_ordinary_recovery_session_v12(&fixture.binding, kind, round.context().template_hash,)
    );
    let complete = round.complete(&partials).map_err(|e| e.to_string())?;
    let tx = Transaction::from_bytes(complete.transaction_bytes()).map_err(|e| e.to_string())?;
    assert_eq!(tx.kernels[0].features, KERNEL_FEAT_HEIGHT_LOCKED);
    assert_eq!(
        tx.outputs[0].commitment.as_bytes(),
        &fixture.binding.punish_recipient_commitment
    );
    for height in [199, 200, 201] {
        let context = ValidationContext {
            current_height: BlockHeight(height),
            chain_id: CHAIN,
            now: Timestamp(0),
        };
        assert_eq!(validate_transaction(&tx, &context).is_ok(), height >= 200);
    }
    // No adaptor is involved; both native ordinary partial equations were
    // checked. This is not funding permission or a real daemon swap.
    assert!(ordinary_v12(&fixture, kind).is_err());
    Ok(())
}

#[test]
fn v23_compensation_refuses_legacy_policy_and_every_mismatched_policy_binding() -> TestResult {
    use dom_scriptless_crypto::XmrOrdinaryRecoveryKindV12;
    let mut fixture = Fixture::new()?;
    let legacy = bounded_terms::policy_for(&mut fixture, false)?;
    let kind = XmrOrdinaryRecoveryKindV12::Compensation;
    assert!(ordinary_with_policy(&fixture, kind, Some(&legacy)).is_err());
    assert!(dom_scriptless_crypto::xmr_bounded_compensation_session_v23(
        &fixture.binding,
        &legacy,
        [1; 32],
    )
    .is_err());
    let policy = bounded_terms::policy_for(&mut fixture, true)?;
    let original = fixture.binding;
    let template_hash = [1; 32];
    let checked = dom_scriptless_crypto::xmr_bounded_compensation_session_v23(
        &original,
        &policy,
        template_hash,
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(
        checked,
        dom_scriptless_crypto::xmr_compensation_session_v23(
            &original,
            template_hash,
            policy.policy().policy_hash().map_err(|e| e.to_string())?,
        )
    );
    assert!(dom_scriptless_crypto::xmr_bounded_compensation_session_v23(
        &original, &policy, [0; 32],
    )
    .is_err());
    for field in 0..11 {
        fixture.binding = original;
        match field {
            0 => fixture.binding.chain_id[0] ^= 1,
            1 => fixture.binding.session_id[0] ^= 1,
            2 => fixture.binding.terms_hash[0] ^= 1,
            3 => fixture.binding.cancel_height += 1,
            4 => fixture.binding.punish_height += 1,
            5 => fixture.binding.reveal_safety_blocks += 1,
            6 => fixture.binding.cancel_fee += 1,
            7 => fixture.binding.refund_fee += 1,
            8 => fixture.binding.punish_fee += 1,
            9 => fixture.binding.refund_recipient_commitment[1] ^= 1,
            _ => fixture.binding.punish_recipient_commitment[1] ^= 1,
        }
        assert!(ordinary_with_policy(&fixture, kind, Some(&policy)).is_err());
        assert!(dom_scriptless_crypto::xmr_bounded_compensation_session_v23(
            &fixture.binding,
            &policy,
            template_hash,
        )
        .is_err());
    }
    Ok(())
}
#[test]
fn v23_graph_derives_the_exact_native_round_ids_and_refuses_foreign_policy() -> TestResult {
    use dom_scriptless_crypto::XmrOrdinaryRecoveryKindV12;
    let mut fixture = Fixture::new()?;
    let legacy = bounded_terms::policy_for(&mut fixture, false)?;
    let legacy_graph =
        verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    assert!(legacy_graph
        .ordinary_recovery_sessions_v23(&legacy)
        .is_err());
    let policy = bounded_terms::policy_for(&mut fixture, true)?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let ids = graph
        .ordinary_recovery_sessions_v23(&policy)
        .map_err(|e| e.to_string())?;
    let (cancel, _) = ordinary_v12(&fixture, XmrOrdinaryRecoveryKindV12::Cancel)?;
    let (compensation, _) = ordinary_with_policy(
        &fixture,
        XmrOrdinaryRecoveryKindV12::Compensation,
        Some(&policy),
    )?;
    assert_eq!(
        ids,
        (
            cancel.context().session_id,
            compensation.context().session_id
        )
    );
    assert_ne!(ids.0, ids.1);
    assert_ne!(ids.0, fixture.binding.session_id);
    assert_ne!(ids.1, fixture.binding.session_id);
    // Signed public transaction bytes are projected to their native unsigned
    // templates. This does not certify any Store journal or authorize funding.
    assert!(graph.ordinary_recovery_sessions_v23(&legacy).is_err());
    assert!(legacy_graph
        .ordinary_recovery_sessions_v23(&policy)
        .is_err());
    Ok(())
}
