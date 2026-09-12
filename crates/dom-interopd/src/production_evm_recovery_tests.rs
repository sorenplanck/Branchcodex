//! Real EVM adapter verification over a mutable deterministic RPC boundary.
//! No network, signer, daemon execution or economic E2E is implied.
use super::*;
use adapter_evm::{
    adapter::test_support::{sample_config, sample_terms},
    binding::{adaptor_address_of_scalar, derive_binding, derive_lock_id},
    mock::MockChain,
};
use route_executor::ExposureSourceV1;
use std::{
    rc::Rc,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct SharedChain(Arc<Mutex<MockChain>>);
impl JsonRpc for SharedChain {
    fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AdapterError> {
        self.0
            .lock()
            .map_err(|_| AdapterError::AdapterUnavailable)?
            .call(method, params)
    }
}

struct Fixture {
    rpc: SharedChain,
    adapter: Rc<EvmAdapter<SharedChain>>,
    terms: LockTerms,
    binding: Digest32,
    lock_id: Digest32,
    scalar: Digest32,
}
impl Fixture {
    fn new() -> Self {
        let config = sample_config();
        let mut scalar = [0; 32];
        scalar[31] = 7;
        let mut terms = sample_terms(&config);
        terms.adaptor_address = adaptor_address_of_scalar(&scalar).expect("valid scalar");
        let binding = derive_binding(config.chain_id, &config.contract, &terms).expect("binding");
        let lock_id = derive_lock_id(&binding, &config.funder).expect("lock id");
        let mut chain = MockChain::new(config.chain_id, config.contract);
        chain.push_block();
        chain
            .push_lock_opened(
                lock_id,
                binding,
                config.funder,
                config.beneficiary,
                terms.asset,
                terms.amount,
                terms.adaptor_address,
                terms.deadline,
            )
            .expect("funding");
        let height = chain.height();
        chain.set_finalized(height);
        let rpc = SharedChain(Arc::new(Mutex::new(chain)));
        let adapter = Rc::new(EvmAdapter::new(config, rpc.clone()).expect("adapter"));
        Self {
            rpc,
            adapter,
            terms,
            binding,
            lock_id,
            scalar,
        }
    }

    fn source(&self) -> ProductionEvmPublicSecretSourceV1<SharedChain> {
        ProductionEvmPublicSecretSourceV1::from_retained_adapter_v4(
            [1; 32],
            [2; 32],
            Rc::clone(&self.adapter),
            self.terms.clone(),
        )
        .expect("retained lock")
    }

    fn claim(&self, finalized: bool) -> PublicExposureV1 {
        let mut chain = self.rpc.0.lock().expect("chain");
        chain.push_block();
        let (height, index) = chain
            .push_claimed(
                self.lock_id,
                self.binding,
                self.terms.beneficiary,
                self.scalar,
            )
            .expect("claim");
        if finalized {
            chain.set_finalized(height);
        }
        PublicExposureV1 {
            source: ExposureSourceV1::Block,
            chain_id: evm_counterparty_chain_id(self.adapter.config().chain_id).0,
            transaction_id: chain.tx_hash_at(height, index as usize).expect("claim tx"),
            evidence_digest: [4; 32],
            observed_at_unix_ms: 1,
        }
    }
}

fn extract(
    source: &mut ProductionEvmPublicSecretSourceV1<SharedChain>,
    exposure: &PublicExposureV1,
) -> Result<RevealedSecretBytes, AuthorityRefusalV1> {
    source.reextract_for_chain(ProductionPublicSecretRequestV1 {
        route_id: [1; 32],
        composition_digest: [2; 32],
        exposure,
    })
}

#[test]
fn late_claim_is_reverified_by_retained_and_reconstructed_sources() {
    let fixture = Fixture::new();
    // Constructor precedes the claim: no expected txid or private scalar is
    // supplied to the source. Its lock terms were authenticated beforehand.
    let mut source = fixture.source();
    let exposure = fixture.claim(true);
    for _ in 0..2 {
        assert_eq!(
            extract(&mut source, &exposure)
                .expect("verified")
                .expose_scalar_bytes(),
            fixture.scalar
        );
    }
    let adapter = EvmAdapter::new(fixture.adapter.config().clone(), fixture.rpc.clone())
        .expect("fresh adapter");
    let mut reopened = ProductionEvmPublicSecretSourceV1::from_retained_adapter_v4(
        [1; 32],
        [2; 32],
        Rc::new(adapter),
        fixture.terms.clone(),
    )
    .expect("fresh observer/source");
    assert_eq!(
        extract(&mut reopened, &exposure)
            .expect("reverified")
            .expose_scalar_bytes(),
        fixture.scalar
    );
}

#[test]
fn unrelated_txid_and_scope_mutations_do_not_poison_later_valid_extraction() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    let valid = fixture.claim(true);
    let mut mutations: [_; 5] = core::array::from_fn(|_| valid.clone());
    mutations[0].transaction_id = [99; 32];
    mutations[1].transaction_id = [0; 32];
    mutations[2].chain_id = [99; 32];
    mutations[3].evidence_digest = [0; 32];
    mutations[4].observed_at_unix_ms = 0;
    for exposure in mutations {
        assert!(extract(&mut source, &exposure).is_err());
    }
    for (route_id, composition_digest) in [([99; 32], [2; 32]), ([1; 32], [99; 32])] {
        assert!(source
            .reextract_for_chain(ProductionPublicSecretRequestV1 {
                route_id,
                composition_digest,
                exposure: &valid
            })
            .is_err());
    }
    assert_eq!(
        extract(&mut source, &valid)
            .expect("not poisoned")
            .expose_scalar_bytes(),
        fixture.scalar
    );
}

#[test]
fn pending_claim_waits_for_finality_and_reorg_does_not_reuse_cached_scalar() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    let exposure = fixture.claim(false);
    assert!(extract(&mut source, &exposure).is_err());
    {
        let mut chain = fixture.rpc.0.lock().expect("chain");
        let height = chain.height();
        chain.set_finalized(height);
    }
    assert!(extract(&mut source, &exposure).is_ok());
    fixture.rpc.0.lock().expect("chain").reorg(1);
    assert!(extract(&mut source, &exposure).is_err());
    let adapter = EvmAdapter::new(fixture.adapter.config().clone(), fixture.rpc.clone())
        .expect("fresh adapter");
    let mut reopened = ProductionEvmPublicSecretSourceV1::from_retained_adapter_v4(
        [1; 32],
        [2; 32],
        Rc::new(adapter),
        fixture.terms.clone(),
    )
    .expect("fresh source");
    assert!(extract(&mut reopened, &exposure).is_err());
}

#[test]
fn refunded_lock_cannot_be_used_as_a_public_secret_source() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    let mut chain = fixture.rpc.0.lock().expect("chain");
    chain.push_block();
    let (height, index) = chain
        .push_refunded(
            fixture.lock_id,
            fixture.binding,
            fixture.adapter.config().funder,
            fixture.terms.amount,
        )
        .expect("refund");
    chain.set_finalized(height);
    let exposure = PublicExposureV1 {
        source: ExposureSourceV1::Block,
        chain_id: source.chain_id(),
        transaction_id: chain.tx_hash_at(height, index as usize).expect("refund tx"),
        evidence_digest: [4; 32],
        observed_at_unix_ms: 1,
    };
    drop(chain);
    assert!(extract(&mut source, &exposure).is_err());
}
