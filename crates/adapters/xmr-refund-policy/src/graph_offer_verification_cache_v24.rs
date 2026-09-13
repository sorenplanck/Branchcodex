//! Memoize only successful pure graph-offer checks over exact public bytes.
//! Never persistent, never a funding/lease/finality/nonce admission mechanism.
use super::{
    Error, SettlementTermsV1, ValidatedXmrCompensationPolicyV11, XmrGraphOfferScopeV22,
    XmrGraphOfferV22,
};
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

const ENTRIES: usize = 8;
// Cache budget only: an input above it still runs the original verifier. The
// current canonical terms include at most 4096 metadata bytes and fit in 8192.
const TERMS_BYTES: usize = 8192;
const POLICY_BYTES: usize = crate::compensation::XMR_COMPENSATION_POLICY_BYTES_V23;
const DOMAIN: &[u8] = b"DOM:XMR:graph-offer-verification-cache:v24\0";
const KEY_BYTES: usize = DOMAIN.len()
    + 3 * 4
    + XmrGraphOfferV22::MAX_BYTES
    + TERMS_BYTES
    + POLICY_BYTES
    + 4 * 32
    + 2 * 8
    + 1;
const RETAINED_BYTES: usize = ENTRIES * KEY_BYTES;

#[derive(Default)]
struct SuccessfulChecksV24 {
    keys: VecDeque<Box<[u8]>>,
    bytes: usize,
}
impl SuccessfulChecksV24 {
    fn contains(&self, key: &[u8]) -> bool {
        self.keys.iter().any(|prior| prior.as_ref() == key)
    }
}

#[derive(Default)]
struct VerificationCacheV24 {
    successful: Mutex<SuccessfulChecksV24>,
    // Entry counter for this layer's verifier body, not nested crypto work.
    #[cfg(test)]
    original_calls: std::sync::atomic::AtomicUsize,
}

static CACHE: OnceLock<VerificationCacheV24> = OnceLock::new();

pub(super) fn verify(
    offer: &XmrGraphOfferV22,
    terms: &SettlementTermsV1,
    policy: &ValidatedXmrCompensationPolicyV11,
    scope: &XmrGraphOfferScopeV22<'_>,
) -> Result<(), Error> {
    verify_using(
        CACHE.get_or_init(VerificationCacheV24::default),
        offer,
        terms,
        policy,
        scope,
    )
}

fn verify_using(
    cache: &VerificationCacheV24,
    offer: &XmrGraphOfferV22,
    terms: &SettlementTermsV1,
    policy: &ValidatedXmrCompensationPolicyV11,
    scope: &XmrGraphOfferScopeV22<'_>,
) -> Result<(), Error> {
    let key = exact_key(offer, terms, policy, scope);
    if let Some(key) = &key {
        if let Ok(successful) = cache.successful.try_lock() {
            // Complete equality, not a digest/pointer/proof-only lookup.
            if successful.contains(key) {
                return Ok(());
            }
        }
    }
    #[cfg(test)]
    cache
        .original_calls
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    offer.verify_uncached_v24(terms, policy, scope)?;
    // No lock during cryptography. Poison/contention only loses an optimization,
    // never changes the original verifier's success/error result.
    if let Some(key) = key {
        if let Ok(mut successful) = cache.successful.try_lock() {
            if !successful.contains(&key) {
                while successful.keys.len() >= ENTRIES
                    || successful.bytes.saturating_add(key.len()) > RETAINED_BYTES
                {
                    let Some(oldest) = successful.keys.pop_front() else {
                        break;
                    };
                    successful.bytes -= oldest.len();
                }
                if successful.keys.try_reserve(1).is_err() {
                    return Ok(());
                }
                successful.bytes += key.len();
                successful.keys.push_back(key.into_boxed_slice());
            }
        }
    }
    Ok(())
}

fn exact_key(
    offer: &XmrGraphOfferV22,
    terms: &SettlementTermsV1,
    policy: &ValidatedXmrCompensationPolicyV11,
    scope: &XmrGraphOfferScopeV22<'_>,
) -> Option<Vec<u8>> {
    // These codecs do not call XmrGraphOfferV22::verify/from_bytes; no recursive
    // lookup and no normalization of the strict decoder's untrusted input.
    let offer = offer.to_bytes().ok()?;
    let terms = terms.canonical_bytes().ok()?;
    let policy_bytes = policy.policy().to_bytes().ok()?;
    if offer.len() > XmrGraphOfferV22::MAX_BYTES
        || terms.len() > TERMS_BYTES
        || policy_bytes.len() > POLICY_BYTES
    {
        return None;
    }
    let size =
        DOMAIN.len() + 3 * 4 + offer.len() + terms.len() + policy_bytes.len() + 4 * 32 + 2 * 8 + 1;
    if size > KEY_BYTES {
        return None;
    }
    let mut key = Vec::new();
    key.try_reserve_exact(size).ok()?;
    key.extend_from_slice(DOMAIN);
    for field in [&offer, &terms, &policy_bytes] {
        key.extend_from_slice(&u32::try_from(field.len()).ok()?.to_be_bytes());
        key.extend_from_slice(field);
    }
    // Also bind all private-field validated-policy projections, not merely the
    // raw policy. Currently these are derived, but equality must remain exact.
    key.extend_from_slice(policy.terms_hash());
    key.extend_from_slice(&policy.margin_noms().to_be_bytes());
    key.extend_from_slice(&policy.collateral_noms().to_be_bytes());
    key.extend_from_slice(scope.chain.as_bytes());
    key.extend_from_slice(&scope.route_id);
    key.extend_from_slice(&scope.participant);
    key.push(scope.direction.to_byte());
    Some(key)
}

#[cfg(test)]
#[path = "graph_offer_verification_cache_v24_tests.rs"]
mod tests;
