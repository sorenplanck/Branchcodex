#![cfg(target_os = "linux")]
//! Native recovery graph custody with retained Linux filesystem restart tests.
//! These are component tests, not live swap evidence.
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

use cap_std::{ambient_authority, fs::Dir};
use dom_scriptless_crypto::XmrRecoverySealKeyV11;
use dom_scriptless_store::{
    XmrRecoveryCustodyErrorV11, XmrRecoveryCustodyRoleV11, XmrRecoveryCustodyScopeV11,
    XmrRecoveryCustodyV11,
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct TestDirectory(PathBuf);
impl TestDirectory {
    fn new() -> TestResult<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "dom-xmr-recovery-v11-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).map_err(|e| e.to_string())?;
        Ok(Self(path))
    }
    fn parent(&self) -> TestResult<Dir> {
        Dir::open_ambient_dir(&self.0, ambient_authority()).map_err(|e| e.to_string())
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn key() -> TestResult<XmrRecoverySealKeyV11> {
    XmrRecoverySealKeyV11::from_bytes(Zeroizing::new([71; 32])).map_err(|e| e.to_string())
}
fn scope(
    fixture: &Fixture,
    digest: [u8; 32],
    role: XmrRecoveryCustodyRoleV11,
) -> XmrRecoveryCustodyScopeV11 {
    XmrRecoveryCustodyScopeV11 {
        binding: fixture.binding,
        graph_digest: digest,
        custody_id: [72; 32],
        role,
    }
}

#[test]
fn v11_private_refund_owner_and_public_counterparty_reopen_exact_custody() -> TestResult {
    let directory = TestDirectory::new()?;
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let witness = AdaptorSecret::from_be_bytes(scalar(7)).map_err(|e| e.to_string())?;
    let private = graph
        .complete_private_refund(&witness)
        .map_err(|e| e.to_string())?;
    for (name, role, private_input) in [
        (
            "u-owner",
            XmrRecoveryCustodyRoleV11::PrivateRefundOwner,
            Some(&private),
        ),
        (
            "t-owner",
            XmrRecoveryCustodyRoleV11::PublicCounterparty,
            None,
        ),
    ] {
        let scope = scope(&fixture, *graph.graph_digest(), role);
        let store = XmrRecoveryCustodyV11::create(
            directory.parent()?,
            name,
            scope,
            &graph,
            key()?,
            private_input,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(
            XmrRecoveryCustodyV11::open_existing(directory.parent()?, name, scope, key()?).err(),
            Some(XmrRecoveryCustodyErrorV11::Busy)
        );
        drop(store);
        for _ in 0..2 {
            let reopened =
                XmrRecoveryCustodyV11::open_existing(directory.parent()?, name, scope, key()?)
                    .map_err(|e| e.to_string())?;
            reopened
                .with_graph(|retained| {
                    assert_eq!(retained.graph_digest(), graph.graph_digest());
                    assert_eq!(retained.cancel_bytes(), graph.cancel_bytes());
                    assert_eq!(retained.punish_bytes(), graph.punish_bytes());
                })
                .map_err(|e| e.to_string())?;
            if role == XmrRecoveryCustodyRoleV11::PrivateRefundOwner {
                reopened
                    .with_private_refund(|retained| {
                        assert_eq!(retained.transaction_hash(), private.transaction_hash());
                        retained.with_secret_bytes(|bytes| {
                            private.with_secret_bytes(|expected| {
                                assert_eq!(bytes, expected);
                            })
                        });
                    })
                    .map_err(|e| e.to_string())?;
            } else {
                assert_eq!(
                    reopened.with_private_refund(|_| ()).err(),
                    Some(XmrRecoveryCustodyErrorV11::Conflict)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn v11_custody_recovers_exact_authenticated_staging_without_new_witnesses() -> TestResult {
    let directory = TestDirectory::new()?;
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let scope = scope(
        &fixture,
        *graph.graph_digest(),
        XmrRecoveryCustodyRoleV11::PublicCounterparty,
    );
    let store =
        XmrRecoveryCustodyV11::create(directory.parent()?, "custody", scope, &graph, key()?, None)
            .map_err(|e| e.to_string())?;
    drop(store);
    let committed = directory.0.join("custody/xmr-recovery-archive-v11.bin");
    let staged = directory
        .0
        .join("custody/.xmr-recovery-archive-v11.staging");
    let exact = std::fs::read(&committed).map_err(|e| e.to_string())?;
    // The surviving durable state of a crash immediately before the no-replace
    // publication. Recovery must authenticate these exact bytes before rename.
    std::fs::rename(&committed, &staged).map_err(|e| e.to_string())?;
    let reopened =
        XmrRecoveryCustodyV11::open_existing(directory.parent()?, "custody", scope, key()?)
            .map_err(|e| e.to_string())?;
    assert!(!staged.exists());
    assert_eq!(std::fs::read(&committed).map_err(|e| e.to_string())?, exact);
    reopened.revalidate().map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn v11_custody_distinguishes_absence_substitution_and_corruption() -> TestResult {
    let directory = TestDirectory::new()?;
    let fixture = Fixture::new()?;
    let graph = verify_xmr_recovery_graph_v11(fixture.request()?).map_err(|e| e.to_string())?;
    let scope = scope(
        &fixture,
        *graph.graph_digest(),
        XmrRecoveryCustodyRoleV11::PublicCounterparty,
    );
    assert_eq!(
        XmrRecoveryCustodyV11::open_existing(directory.parent()?, "missing", scope, key()?).err(),
        Some(XmrRecoveryCustodyErrorV11::NotFound)
    );
    assert!(!directory.0.join("missing").exists());
    let store =
        XmrRecoveryCustodyV11::create(directory.parent()?, "custody", scope, &graph, key()?, None)
            .map_err(|e| e.to_string())?;
    drop(store);
    let mut different = scope;
    different.binding.session_id[0] ^= 1;
    assert_eq!(
        XmrRecoveryCustodyV11::open_existing(directory.parent()?, "custody", different, key()?)
            .err(),
        Some(XmrRecoveryCustodyErrorV11::Conflict)
    );
    let committed = directory.0.join("custody/xmr-recovery-archive-v11.bin");
    let mut bytes = std::fs::read(&committed).map_err(|e| e.to_string())?;
    let last = bytes.last_mut().ok_or("empty envelope")?;
    *last ^= 1;
    std::fs::write(&committed, &bytes).map_err(|e| e.to_string())?;
    assert_eq!(
        XmrRecoveryCustodyV11::open_existing(directory.parent()?, "custody", scope, key()?).err(),
        Some(XmrRecoveryCustodyErrorV11::InvalidArchive)
    );
    std::fs::remove_file(&committed).map_err(|e| e.to_string())?;
    assert_eq!(
        XmrRecoveryCustodyV11::open_existing(directory.parent()?, "custody", scope, key()?).err(),
        Some(XmrRecoveryCustodyErrorV11::NotFound)
    );
    assert!(!committed.exists());
    Ok(())
}
