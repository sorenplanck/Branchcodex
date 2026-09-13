//! Exact public signing-equation replay, never retained Store/F7 authority.
//!
//! Every caller still audits transport, authenticates its origin, loads and
//! checks all durable revisions/successors, and enforces its live capability.
//! Only the deterministic public semantic verifier's result is memoized here.
//! The original verifier and its frozen source are unchanged. This cache holds
//! no secret, private nonce, observation, authorization, revision handle or
//! open Store. Origin pins separate callers but do not replace their audits.
use super::super::*;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

const DOMAIN_V25: &[u8] = b"DOM:public-signing-semantics-exact:v25";
const CAPACITY_V25: usize = 64;
const MAX_KEY_BYTES_V25: usize = 32 * 1024;

#[derive(Clone, Copy)]
pub(in super::super) struct PublicSigningScopeV25 {
    family: u8,
    pins: [[u8; 32]; 7],
}

impl PublicSigningScopeV25 {
    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn graph(
        route: [u8; 32],
        parent: [u8; 32],
        terms: [u8; 32],
        input_session: [u8; 32],
        origin: [u8; 32],
        binding: [u8; 32],
        start_record: [u8; 32],
    ) -> Self {
        Self {
            family: 1,
            pins: [
                route,
                parent,
                terms,
                input_session,
                origin,
                binding,
                start_record,
            ],
        }
    }

    pub(in super::super) fn funding(
        binding: [u8; 32],
        start_record: [u8; 32],
        terms: [u8; 32],
    ) -> Self {
        Self {
            family: 2,
            pins: [
                binding,
                start_record,
                terms,
                [0; 32],
                [0; 32],
                [0; 32],
                [0; 32],
            ],
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn claim(
        binding: [u8; 32],
        start_record: [u8; 32],
        terms: [u8; 32],
        issued: [u8; 32],
        consumption: [u8; 32],
        issuance: [u8; 32],
        gate: [u8; 32],
    ) -> Self {
        Self {
            family: 3,
            pins: [
                binding,
                start_record,
                terms,
                issued,
                consumption,
                issuance,
                gate,
            ],
        }
    }

    fn eligible(self, purpose: PurposeV1) -> bool {
        matches!(
            (self.family, purpose),
            (1, PurposeV1::Refund | PurposeV1::RefundAdaptor)
                | (2, PurposeV1::Funding)
                | (3, PurposeV1::ClaimAdaptor)
        )
    }
}

struct ExactKeyV25(Vec<u8>);

impl ExactKeyV25 {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn bytes(&mut self, bytes: &[u8]) -> Option<()> {
        let length = self.0.len().checked_add(bytes.len())?;
        if length > MAX_KEY_BYTES_V25 {
            return None;
        }
        self.0.try_reserve_exact(bytes.len()).ok()?;
        self.0.extend_from_slice(bytes);
        Some(())
    }

    fn len(&mut self, length: usize) -> Option<()> {
        self.bytes(&u32::try_from(length).ok()?.to_le_bytes())
    }

    fn delimited(&mut self, bytes: &[u8]) -> Option<()> {
        self.len(bytes.len())?;
        self.bytes(bytes)
    }

    fn optional32(&mut self, value: Option<&[u8; 32]>) -> Option<()> {
        self.bytes(&[u8::from(value.is_some())])?;
        if let Some(value) = value {
            self.bytes(value)?;
        }
        Some(())
    }

    // Exact original Transaction canonical encoding, bounded/fallibly reserved.
    // Exhaustive destructuring makes additions to ANY represented type fail
    // compilation until key coverage is reviewed. Tests pin against to_bytes().
    fn transaction(&mut self, transaction: &Transaction) -> Option<()> {
        use dom_consensus::{TransactionInput, TransactionKernel, TransactionOutput};
        let Transaction {
            inputs,
            outputs,
            kernels,
            offset,
        } = transaction;
        self.len(inputs.len())?;
        for input in inputs {
            let TransactionInput { commitment } = input;
            self.bytes(commitment.as_bytes())?;
        }
        self.len(outputs.len())?;
        for output in outputs {
            let TransactionOutput { commitment, proof } = output;
            self.bytes(commitment.as_bytes())?;
            self.delimited(proof)?;
        }
        self.len(kernels.len())?;
        for kernel in kernels {
            let TransactionKernel {
                features,
                fee,
                lock_height,
                excess,
                excess_signature,
            } = kernel;
            self.bytes(&[*features])?;
            self.bytes(&fee.noms().to_le_bytes())?;
            self.bytes(&lock_height.to_le_bytes())?;
            self.bytes(excess.as_bytes())?;
            self.bytes(excess_signature)?;
        }
        self.bytes(offset)
    }
}

fn exact_key_v25<B: SigningSemanticBindingAccessV1>(
    scope: PublicSigningScopeV25,
    chain: &[u8; 32],
    session: [u8; 32],
    purpose: PurposeV1,
    binding: &B,
    round: &SigningRoundSemanticViewV23<'_>,
) -> Option<ExactKeyV25> {
    // Ineligible/malformed inputs ALWAYS go to the unchanged original, whose
    // exact error precedence (including purpose refusals) remains authoritative.
    if !scope.eligible(purpose)
        || *chain == [0; 32]
        || session == [0; 32]
        || binding.participant_count() != 2
        || binding.template_hash() == &[0; 32]
        || !(4..=6).contains(&round.accepted_messages.len())
    {
        return None;
    }
    let mut key = ExactKeyV25::new();
    key.delimited(DOMAIN_V25)?;
    key.bytes(&[scope.family])?;
    for pin in scope.pins {
        key.bytes(&pin)?;
    }
    key.bytes(chain)?;
    key.bytes(&session)?;
    key.bytes(&[purpose.to_byte()])?;
    key.len(binding.participant_count())?;
    for index in 0..binding.participant_count() {
        let participant = binding.participant(index)?;
        key.bytes(participant.participant_id)?;
        key.bytes(&participant.signing_public_key.to_compressed_bytes())?;
        key.bytes(&[participant.direction.to_byte()])?;
        // Include the actual trait result too; a future custom signing-index
        // mapping cannot alias a previously memoized canonical roster.
        key.bytes(
            &binding
                .signing_index(participant.participant_id)
                .ok()?
                .to_le_bytes(),
        )?;
    }
    key.bytes(binding.template_hash())?;
    key.bytes(&u64::try_from(binding.kernel_index()).ok()?.to_le_bytes())?;
    key.bytes(&[u8::from(binding.adaptor_point().is_some())])?;
    if let Some(point) = binding.adaptor_point() {
        key.bytes(&point.to_compressed_bytes())?;
    }
    // The template is self-delimiting, including every output's FULL proof and
    // every kernel's existing signature, not merely its template/message hash.
    key.transaction(binding.transaction_template())?;
    key.bytes(&round.round_start_transcript_hash)?;
    for sequence in round.sender_sequence_bases {
        key.bytes(&sequence.to_le_bytes())?;
    }
    key.bytes(&round.terminal_transcript_hash)?;
    key.optional32(round.reveal_transcript_hash.as_ref())?;
    key.len(round.accepted_messages.len())?;
    for bytes in round.accepted_messages {
        key.delimited(bytes)?;
    }
    Some(key)
}

struct EntryV25 {
    exact: ExactKeyV25,
    plain_signature: Option<[u8; 65]>,
}

#[derive(Default)]
struct CacheV25 {
    entries: Mutex<VecDeque<EntryV25>>,
    #[cfg(test)]
    original_calls: std::sync::atomic::AtomicUsize,
}

static CACHE_V25: OnceLock<CacheV25> = OnceLock::new();

pub(in super::super) fn verify_v25<B: SigningSemanticBindingAccessV1>(
    scope: PublicSigningScopeV25,
    chain: &[u8; 32],
    session: [u8; 32],
    purpose: PurposeV1,
    binding: &B,
    round: &SigningRoundSemanticViewV23<'_>,
) -> Result<Option<SchnorrSignature>, SessionStoreError> {
    verify_using_v25(
        CACHE_V25.get_or_init(CacheV25::default),
        scope,
        chain,
        session,
        purpose,
        binding,
        round,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_using_v25<B: SigningSemanticBindingAccessV1>(
    cache: &CacheV25,
    scope: PublicSigningScopeV25,
    chain: &[u8; 32],
    session: [u8; 32],
    purpose: PurposeV1,
    binding: &B,
    round: &SigningRoundSemanticViewV23<'_>,
) -> Result<Option<SchnorrSignature>, SessionStoreError> {
    let key = exact_key_v25(scope, chain, session, purpose, binding, round);
    if let Some(exact) = &key {
        if let Ok(entries) = cache.entries.try_lock() {
            if let Some(entry) = entries.iter().find(|entry| entry.exact.0 == exact.0) {
                match entry.plain_signature {
                    None => return Ok(None),
                    Some(bytes) => {
                        if let Ok(signature) = SchnorrSignature::from_bytes(&bytes) {
                            return Ok(Some(signature));
                        }
                    }
                }
            }
        }
    }
    // No mutex is held through the original verifier. No Store operation or
    // external callback is substituted by the memo; failures are never stored.
    #[cfg(test)]
    cache
        .original_calls
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let result = validate_signing_round_semantics_v23(chain, session, purpose, binding, round)?;
    if let Some(exact) = key {
        if let Ok(mut entries) = cache.entries.try_lock() {
            if !entries.iter().any(|entry| entry.exact.0 == exact.0) {
                if entries.len() == CAPACITY_V25 {
                    entries.pop_front();
                }
                if entries.try_reserve(1).is_ok() {
                    entries.push_back(EntryV25 {
                        exact,
                        plain_signature: result.as_ref().map(SchnorrSignature::to_bytes),
                    });
                }
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
#[path = "public_signing_semantics_cache_v25_tests.rs"]
mod tests;
