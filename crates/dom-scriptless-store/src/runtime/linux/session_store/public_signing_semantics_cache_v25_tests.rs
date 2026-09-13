//! Real two-party Schnorr transcripts; no Store/F7 authority is manufactured.
//! The deliberately minimal transaction is a semantic-verifier input, not a
//! spendable/economically validated transaction. No Bulletproof fixture runs.
use super::*;
use crate::runtime::linux::session_store::evidence_only_staging::transport_signed_bytes;
use dom_adaptor::ParticipantPublicNoncesV1;
use dom_consensus::{TransactionInput, TransactionKernel, TransactionOutput};
use dom_core::{Amount, KERNEL_FEAT_PLAIN};
use dom_crypto::{pedersen::Commitment, schnorr_partial_sign, SecretKey};
use dom_scriptless_primitives::secret_scalar_mul_add_assign;
use rand_core::{OsRng, RngCore};
use std::sync::atomic::Ordering;
use zeroize::Zeroizing;

fn secret(value: u8) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[31] = value;
    SecretKey::from_bytes(&bytes).unwrap()
}

fn nonce() -> SecretKey {
    let mut bytes = Zeroizing::new([0; 32]);
    for _ in 0..128 {
        OsRng.try_fill_bytes(bytes.as_mut()).unwrap();
        if let Ok(secret) = SecretKey::from_bytes(bytes.as_ref()) {
            return secret;
        }
    }
    panic!("bounded test nonce sampling exhausted");
}

#[derive(Clone)]
struct Participant {
    id: [u8; 32],
    key: PublicKey,
    direction: DirectionV1,
}

#[derive(Clone)]
struct Binding {
    participants: Vec<Participant>,
    template: Transaction,
    template_hash: [u8; 32],
    kernel_index: usize,
    adaptor: Option<PublicKey>,
    index_override: Option<[u16; 2]>,
}

impl SigningSemanticBindingAccessV1 for Binding {
    fn participant_count(&self) -> usize {
        self.participants.len()
    }
    fn participant(&self, index: usize) -> Option<SigningSemanticParticipantRefV1<'_>> {
        self.participants
            .get(index)
            .map(|p| SigningSemanticParticipantRefV1 {
                participant_id: &p.id,
                signing_public_key: &p.key,
                direction: p.direction,
            })
    }
    fn transaction_template(&self) -> &Transaction {
        &self.template
    }
    fn template_hash(&self) -> &[u8; 32] {
        &self.template_hash
    }
    fn kernel_index(&self) -> usize {
        self.kernel_index
    }
    fn adaptor_point(&self) -> Option<&PublicKey> {
        self.adaptor.as_ref()
    }
    fn signing_index(&self, id: &[u8; 32]) -> Result<u16, SessionStoreError> {
        let index = self
            .participants
            .iter()
            .position(|p| &p.id == id)
            .ok_or(SessionStoreError::Quarantined)?;
        if let Some(indices) = self.index_override {
            return indices
                .get(index)
                .copied()
                .ok_or(SessionStoreError::Quarantined);
        }
        let mut keys: Vec<_> = self
            .participants
            .iter()
            .map(|p| p.key.to_compressed_bytes())
            .collect();
        keys.sort_unstable();
        keys.iter()
            .position(|key| key == &self.participants[index].key.to_compressed_bytes())
            .and_then(|i| u16::try_from(i).ok())
            .ok_or(SessionStoreError::Quarantined)
    }
}

#[derive(Clone)]
struct Fixture {
    scope: PublicSigningScopeV25,
    chain: [u8; 32],
    session: [u8; 32],
    purpose: PurposeV1,
    binding: Binding,
    start: [u8; 32],
    bases: [u64; 2],
    terminal: [u8; 32],
    reveal: Option<[u8; 32]>,
    messages: Vec<Vec<u8>>,
}

impl Fixture {
    fn new(purpose: PurposeV1) -> Self {
        let chain = [0x19; 32];
        let session = [0x27; 32];
        let mut keys = [secret(3), secret(5)];
        keys.sort_by_key(|key| key.public_key().to_compressed_bytes());
        let participants = keys
            .iter()
            .enumerate()
            .map(|(index, key)| Participant {
                id: [0x31 + index as u8; 32],
                key: key.public_key(),
                direction: if index == 0 {
                    DirectionV1::Initiator
                } else {
                    DirectionV1::Responder
                },
            })
            .collect::<Vec<_>>();
        let aggregate_key = aggregate_public_nonces_v1(
            &participants
                .iter()
                .map(|p| p.key.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let template = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(7).unwrap(),
                lock_height: 0,
                excess: Commitment::from_compressed_bytes(&aggregate_key.to_compressed_bytes())
                    .unwrap(),
                excess_signature: [0; 65],
            }],
            offset: [0; 32],
        };
        let (_, template_hash) = canonical_template_v1(&template).unwrap();
        let adaptor = matches!(purpose, PurposeV1::ClaimAdaptor | PurposeV1::RefundAdaptor)
            .then(|| secret(29).public_key());
        let private_nonces = [[nonce(), nonce()], [nonce(), nonce()]];
        let public_nonces = (0..2)
            .map(|actor| ParticipantPublicNoncesV1 {
                participant_index: actor as u16,
                signing_key: participants[actor].key.clone(),
                first_nonce: private_nonces[actor][0].public_key(),
                second_nonce: private_nonces[actor][1].public_key(),
            })
            .collect::<Vec<_>>();
        let factor = binding_factor_v1(
            &BindingContextV1 {
                chain_id: chain,
                session_id: session,
                purpose,
                template_hash,
            },
            &public_nonces,
            adaptor.as_ref(),
        )
        .unwrap();
        let effective = public_nonces
            .iter()
            .map(|p| {
                factor
                    .bind_public_nonces(&p.first_nonce, &p.second_nonce)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let aggregate_nonce = aggregate_public_nonces_v1(&effective).unwrap();
        let aggregate_hat = if let Some(point) = &adaptor {
            aggregate_public_nonces_v1(&[aggregate_nonce, point.clone()]).unwrap()
        } else {
            aggregate_nonce
        };
        let message = scriptless_kernel_message_digest_v1(&template.kernels[0]);
        let partials = (0..2)
            .map(|actor| {
                let mut bound = Zeroizing::new(private_nonces[actor][0].to_be_bytes_raw());
                let second = Zeroizing::new(private_nonces[actor][1].to_be_bytes_raw());
                secret_scalar_mul_add_assign(&mut bound, &second, &factor.to_be_bytes()).unwrap();
                let bound = SecretKey::from_bytes(bound.as_ref()).unwrap();
                PartialSignatureV1::new(
                    purpose,
                    actor as u16,
                    template_hash,
                    schnorr_partial_sign(
                        &keys[actor],
                        &bound,
                        &aggregate_hat,
                        &aggregate_key,
                        &chain,
                        message.as_bytes(),
                    )
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let start = [0x39; 32];
        let bases = [4, 9];
        let mut terminal = start;
        let mut messages = Vec::new();
        let mut reveal = None;
        for position in 0..6 {
            let actor = position % 2;
            let kind = 0x0c + (position / 2) as u8;
            let payload = match position / 2 {
                0 => NonceCommitmentV1::new(
                    purpose,
                    actor as u16,
                    *nonce_commitment_hash_v1(
                        &chain,
                        &session,
                        &participants[actor].id,
                        purpose,
                        &template_hash,
                        &public_nonces[actor].first_nonce,
                        &public_nonces[actor].second_nonce,
                        adaptor.as_ref(),
                    )
                    .unwrap()
                    .as_bytes(),
                )
                .to_bytes()
                .to_vec(),
                1 => NonceRevealV1::new(
                    purpose,
                    actor as u16,
                    public_nonces[actor].first_nonce.clone(),
                    public_nonces[actor].second_nonce.clone(),
                )
                .to_bytes()
                .to_vec(),
                2 => partials[actor].to_bytes().to_vec(),
                _ => unreachable!(),
            };
            let bytes = transport_signed_bytes(
                &keys[actor],
                chain,
                session,
                participants[actor].id,
                bases[actor] + (position / 2) as u64,
                terminal,
                kind,
                &payload,
            )
            .unwrap();
            let envelope = ParsedTransportEnvelopeV1::parse(&bytes).unwrap();
            envelope.verify(&participants[actor].key).unwrap();
            terminal = advance_transcript_hash_v1(
                &terminal,
                &envelope.message_digest,
                participants[actor].direction,
                signing_phase_for_message(kind).unwrap(),
            );
            if position == 3 {
                reveal = Some(terminal);
            }
            messages.push(bytes);
        }
        let scope = match purpose {
            PurposeV1::Funding => PublicSigningScopeV25::funding([1; 32], [2; 32], [3; 32]),
            PurposeV1::ClaimAdaptor => PublicSigningScopeV25::claim(
                [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], [7; 32],
            ),
            _ => PublicSigningScopeV25::graph(
                [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], [7; 32],
            ),
        };
        // Only public data survives fixture construction; no private nonce or
        // signing key is retained by either the fixture or the memo.
        Self {
            scope,
            chain,
            session,
            purpose,
            binding: Binding {
                participants,
                template,
                template_hash,
                kernel_index: 0,
                adaptor,
                index_override: None,
            },
            start,
            bases,
            terminal,
            reveal,
            messages,
        }
    }

    fn view(&self) -> SigningRoundSemanticViewV23<'_> {
        SigningRoundSemanticViewV23 {
            round_start_transcript_hash: self.start,
            sender_sequence_bases: self.bases,
            accepted_messages: &self.messages,
            terminal_transcript_hash: self.terminal,
            reveal_transcript_hash: self.reveal,
        }
    }
    fn original(&self) -> Result<Option<SchnorrSignature>, SessionStoreError> {
        validate_signing_round_semantics_v23(
            &self.chain,
            self.session,
            self.purpose,
            &self.binding,
            &self.view(),
        )
    }
    fn memo(&self, cache: &CacheV25) -> Result<Option<SchnorrSignature>, SessionStoreError> {
        verify_using_v25(
            cache,
            self.scope,
            &self.chain,
            self.session,
            self.purpose,
            &self.binding,
            &self.view(),
        )
    }
    fn exact(&self) -> Option<Vec<u8>> {
        exact_key_v25(
            self.scope,
            &self.chain,
            self.session,
            self.purpose,
            &self.binding,
            &self.view(),
        )
        .map(|k| k.0)
    }
    fn truncate(&mut self, count: usize) {
        self.messages.truncate(count);
        self.terminal = self.start;
        self.reveal = None;
        for (index, bytes) in self.messages.iter().enumerate() {
            let envelope = ParsedTransportEnvelopeV1::parse(bytes).unwrap();
            self.terminal = advance_transcript_hash_v1(
                &self.terminal,
                &envelope.message_digest,
                self.binding.participants[index % 2].direction,
                signing_phase_for_message(envelope.message_type).unwrap(),
            );
            if index == 3 {
                self.reveal = Some(self.terminal);
            }
        }
    }
}

fn outcome(
    value: Result<Option<SchnorrSignature>, SessionStoreError>,
) -> Result<Option<[u8; 65]>, String> {
    value
        .map(|signature| signature.map(|s| s.to_bytes()))
        .map_err(|e| format!("{e:?}"))
}
fn calls(cache: &CacheV25) -> usize {
    cache.original_calls.load(Ordering::Relaxed)
}

#[test]
fn public_signing_replay_cold_plus_warm64_matches_original_for_all_native_purposes_v25() {
    for purpose in [
        PurposeV1::Funding,
        PurposeV1::Refund,
        PurposeV1::ClaimAdaptor,
        PurposeV1::RefundAdaptor,
    ] {
        let fixture = Fixture::new(purpose);
        let expected = outcome(fixture.original()).unwrap();
        for prefix in 4..=6 {
            let mut prefix_fixture = fixture.clone();
            prefix_fixture.truncate(prefix);
            let cache = CacheV25::default();
            let expected = outcome(prefix_fixture.original());
            assert!(expected.is_ok());
            assert_eq!(outcome(prefix_fixture.memo(&cache)), expected);
            assert_eq!(outcome(prefix_fixture.memo(&cache)), expected);
            assert_eq!(calls(&cache), 1);
        }
        let cache = CacheV25::default();
        let original_start = std::time::Instant::now();
        for _ in 0..64 {
            assert_eq!(outcome(fixture.original()), Ok(expected));
        }
        let original_elapsed = original_start.elapsed();
        let memo_start = std::time::Instant::now();
        let cold_start = std::time::Instant::now();
        assert_eq!(outcome(fixture.memo(&cache)), Ok(expected));
        let cold = cold_start.elapsed();
        for _ in 0..63 {
            assert_eq!(outcome(fixture.memo(&cache)), Ok(expected));
        }
        let memo_elapsed = memo_start.elapsed();
        assert_eq!(calls(&cache), 1);
        assert_eq!(
            outcome(verify_v25(
                fixture.scope,
                &fixture.chain,
                fixture.session,
                fixture.purpose,
                &fixture.binding,
                &fixture.view()
            )),
            Ok(expected)
        );
        eprintln!("PUBLIC_SIGNING_SEMANTICS_TIMING_V25 purpose={} original_calls=64 memo_original_calls=1 original_us={} cold_us={} cold_plus_63_warm_us={} scope=public_semantics_only_not_store_audit_or_swap",
            purpose.to_byte(), original_elapsed.as_micros(), cold.as_micros(), memo_elapsed.as_micros());
    }
}

#[test]
fn every_public_signing_key_field_changes_identity_and_preserves_original_result_v25() {
    let fixture = Fixture::new(PurposeV1::RefundAdaptor);
    let original_key = fixture.exact().unwrap();
    let mut mutations: Vec<Fixture> = Vec::new();
    macro_rules! change { ($value:ident, $body:block) => {{ let mut $value = fixture.clone(); $body mutations.push($value); }}; }
    change!(f, {
        f.chain[0] ^= 1;
    });
    change!(f, {
        f.session[0] ^= 1;
    });
    change!(f, {
        f.purpose = PurposeV1::Refund;
    });
    change!(f, {
        f.scope.family = 2;
    });
    for index in 0..7 {
        change!(f, {
            f.scope.pins[index][0] ^= 1;
        });
    }
    for index in 0..2 {
        change!(f, {
            f.binding.participants[index].id[0] ^= 1;
        });
        change!(f, {
            f.binding.participants[index].key = secret(13).public_key();
        });
        change!(f, {
            f.binding.participants[index].direction = if index == 0 {
                DirectionV1::Responder
            } else {
                DirectionV1::Initiator
            };
        });
        change!(f, {
            f.bases[index] += 1;
        });
    }
    change!(f, {
        f.binding.participants.swap(0, 1);
    });
    change!(f, {
        f.binding.participants.pop();
    });
    change!(f, {
        f.binding.index_override = Some([1, 0]);
    });
    change!(f, {
        f.binding.template_hash[0] ^= 1;
    });
    change!(f, {
        f.binding.kernel_index = 1;
    });
    change!(f, {
        f.binding.adaptor = Some(secret(31).public_key());
    });
    change!(f, {
        f.binding.adaptor = None;
    });
    change!(f, {
        f.binding.template.kernels[0].features ^= 2;
    });
    change!(f, {
        f.binding.template.kernels[0].fee = Amount::from_noms(8).unwrap();
    });
    change!(f, {
        f.binding.template.kernels[0].lock_height += 1;
    });
    change!(f, {
        f.binding.template.kernels[0].excess =
            Commitment::from_compressed_bytes(&secret(13).public_key().to_compressed_bytes())
                .unwrap();
    });
    change!(f, {
        f.binding.template.kernels[0].excess_signature[0] ^= 1;
    });
    change!(f, {
        f.binding.template.offset[0] ^= 1;
    });
    change!(f, {
        f.binding.template.inputs.push(TransactionInput {
            commitment: Commitment::from_compressed_bytes(
                &secret(13).public_key().to_compressed_bytes(),
            )
            .unwrap(),
        });
    });
    change!(f, {
        f.binding.template.outputs.push(TransactionOutput {
            commitment: Commitment::from_compressed_bytes(
                &secret(17).public_key().to_compressed_bytes(),
            )
            .unwrap(),
            proof: vec![1, 2, 3],
        });
    });
    change!(f, {
        f.start[0] ^= 1;
    });
    change!(f, {
        f.terminal[0] ^= 1;
    });
    change!(f, {
        f.reveal = None;
    });
    change!(f, {
        f.reveal.as_mut().unwrap()[0] ^= 1;
    });
    for index in 0..6 {
        change!(f, {
            f.messages[index][112] ^= 1;
        });
        change!(f, {
            let last = f.messages[index].len() - 1;
            f.messages[index][last] ^= 1;
        });
    }
    change!(f, {
        f.messages.swap(0, 1);
    });
    change!(f, {
        f.messages[5].push(0);
    });
    change!(f, {
        f.messages.pop();
    });
    for changed in mutations {
        assert!(changed.exact().as_ref() != Some(&original_key));
        let cache = CacheV25::default();
        assert!(fixture.memo(&cache).is_ok());
        let expected = outcome(changed.original());
        assert_eq!(outcome(changed.memo(&cache)), expected);
        assert_eq!(calls(&cache), 2, "mutation must invoke the original");
        if expected.is_err() {
            assert_eq!(outcome(changed.memo(&cache)), expected);
            assert_eq!(calls(&cache), 3, "failure cannot be memoized");
        }
    }
}

#[test]
fn bounded_transaction_key_matches_complete_original_codec_v25() {
    let fixture = Fixture::new(PurposeV1::Funding);
    let mut transaction = fixture.binding.template.clone();
    for byte in [13, 17] {
        transaction.inputs.push(TransactionInput {
            commitment: Commitment::from_compressed_bytes(
                &secret(byte).public_key().to_compressed_bytes(),
            )
            .unwrap(),
        });
        transaction.outputs.push(TransactionOutput {
            commitment: Commitment::from_compressed_bytes(
                &secret(byte + 2).public_key().to_compressed_bytes(),
            )
            .unwrap(),
            proof: vec![byte; usize::from(byte)],
        });
    }
    let mut second_kernel = transaction.kernels[0].clone();
    second_kernel.features = 2;
    second_kernel.fee = Amount::from_noms(19).unwrap();
    second_kernel.lock_height = 23;
    second_kernel.excess_signature = [29; 65];
    transaction.kernels.push(second_kernel);
    transaction.offset = [31; 32];
    let mut key = ExactKeyV25::new();
    key.transaction(&transaction).unwrap();
    assert_eq!(key.0, transaction.to_bytes().unwrap());
    for mutate in 0..4 {
        let mut changed = transaction.clone();
        match mutate {
            0 => changed.inputs.swap(0, 1),
            1 => changed.outputs.swap(0, 1),
            2 => changed.outputs[0].proof.push(0),
            3 => changed.kernels.swap(0, 1),
            _ => unreachable!(),
        }
        let mut different = ExactKeyV25::new();
        different.transaction(&changed).unwrap();
        assert_eq!(different.0, changed.to_bytes().unwrap());
        assert_ne!(different.0, key.0);
    }
}

#[test]
fn unsigned_candidate_and_authenticated_envelope_never_alias_in_public_memo_v25() {
    let signed = Fixture::new(PurposeV1::Funding);
    let mut candidate = signed.clone();
    let message = candidate.messages.last_mut().unwrap();
    let signature_start = message.len() - 65;
    message[signature_start..].fill(0);
    assert_ne!(candidate.exact(), signed.exact());
    let expected = outcome(signed.original());
    assert_eq!(outcome(candidate.original()), expected);
    let cache = CacheV25::default();
    assert_eq!(outcome(candidate.memo(&cache)), expected);
    assert_eq!(outcome(signed.memo(&cache)), expected);
    assert_eq!(calls(&cache), 2);
    assert!(ParsedTransportEnvelopeV1::parse(&candidate.messages[5])
        .unwrap()
        .verify(&signed.binding.participants[1].key)
        .is_err());
    ParsedTransportEnvelopeV1::parse(&signed.messages[5])
        .unwrap()
        .verify(&signed.binding.participants[1].key)
        .unwrap();
}

#[test]
fn malformed_prefix_purpose_and_missing_fields_preserve_uncached_errors_v25() {
    let fixture = Fixture::new(PurposeV1::Funding);
    for case in 0..6 {
        let mut changed = fixture.clone();
        match case {
            0 => changed.chain = [0; 32],
            1 => changed.session = [0; 32],
            2 => changed.purpose = PurposeV1::Sponsor,
            3 => changed.messages.push(changed.messages[0].clone()),
            4 => changed.messages[4].truncate(1),
            5 => changed.binding.template_hash = [0; 32],
            _ => unreachable!(),
        }
        let expected = outcome(changed.original());
        assert!(expected.is_err());
        let cache = CacheV25::default();
        for _ in 0..2 {
            assert_eq!(outcome(changed.memo(&cache)), expected);
        }
        assert_eq!(calls(&cache), 2);
        assert!(cache.entries.lock().unwrap().is_empty());
    }
    for prefix in 0..4 {
        let mut changed = fixture.clone();
        changed.truncate(prefix);
        assert!(changed.exact().is_none());
        let cache = CacheV25::default();
        for _ in 0..2 {
            assert_eq!(outcome(changed.memo(&cache)), outcome(changed.original()));
        }
        assert_eq!(calls(&cache), 2);
    }
}

#[test]
fn public_signing_memo_capacity_evicts_without_replacing_original_semantics_v25() {
    let fixture = Fixture::new(PurposeV1::Funding);
    let expected = outcome(fixture.original());
    let cache = CacheV25::default();
    for index in 0..=CAPACITY_V25 {
        let mut changed = fixture.clone();
        changed.scope.pins[0][..8].copy_from_slice(&(index as u64).to_le_bytes());
        assert_eq!(outcome(changed.memo(&cache)), expected);
    }
    assert_eq!(calls(&cache), CAPACITY_V25 + 1);
    {
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.len(), CAPACITY_V25);
        assert!(entries
            .iter()
            .all(|entry| entry.exact.0.len() <= MAX_KEY_BYTES_V25));
    }
    let mut newest = fixture.clone();
    newest.scope.pins[0][..8].copy_from_slice(&(CAPACITY_V25 as u64).to_le_bytes());
    assert_eq!(outcome(newest.memo(&cache)), expected);
    assert_eq!(calls(&cache), CAPACITY_V25 + 1);
    let mut oldest = fixture;
    oldest.scope.pins[0][..8].fill(0);
    assert_eq!(outcome(oldest.memo(&cache)), expected);
    assert_eq!(calls(&cache), CAPACITY_V25 + 2);
}

#[test]
fn busy_or_poisoned_public_signing_memo_always_calls_original_v25() {
    let fixture = Fixture::new(PurposeV1::Funding);
    let expected = outcome(fixture.original());
    let cache = CacheV25::default();
    assert_eq!(outcome(fixture.memo(&cache)), expected);
    let guard = cache.entries.lock().unwrap();
    assert_eq!(outcome(fixture.memo(&cache)), expected);
    assert_eq!(calls(&cache), 2);
    drop(guard);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = cache.entries.lock().unwrap();
        panic!("synthetic public cache poison");
    }))
    .is_err());
    for _ in 0..2 {
        assert_eq!(outcome(fixture.memo(&cache)), expected);
    }
    assert_eq!(calls(&cache), 4);
}

#[test]
fn oversized_public_operands_fall_back_without_new_protocol_limits_v25() {
    let mut fixture = Fixture::new(PurposeV1::Funding);
    // Semantic replay does not validate output proofs; the original whole-
    // transaction validators remain separate and cannot be bypassed by this.
    fixture.binding.template.outputs.push(TransactionOutput {
        commitment: Commitment::from_compressed_bytes(
            &secret(17).public_key().to_compressed_bytes(),
        )
        .unwrap(),
        proof: vec![0; MAX_KEY_BYTES_V25],
    });
    assert!(fixture.exact().is_none());
    let expected = outcome(fixture.original());
    assert!(expected.is_ok());
    let cache = CacheV25::default();
    for _ in 0..2 {
        assert_eq!(outcome(fixture.memo(&cache)), expected);
    }
    assert_eq!(calls(&cache), 2);
    assert!(cache.entries.lock().unwrap().is_empty());
    let mut bounded = ExactKeyV25::new();
    bounded.bytes(&vec![0; MAX_KEY_BYTES_V25]).unwrap();
    assert!(bounded.bytes(&[1]).is_none());
    assert_eq!(bounded.0.len(), MAX_KEY_BYTES_V25);
}
