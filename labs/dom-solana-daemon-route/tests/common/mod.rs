//! The provisioned route every test in this directory asserts against.
//!
//! A thin wrapper now: the route itself is provisioned by `laboratory::provision`, which
//! lives in the crate because a ceremony has to be driven by a program and not by a test
//! harness. What remains here is the two temporary directories and the accessors the tests
//! read through.
//!
// One shared module compiled into each test binary, so items a given binary does not reach
// are not dead code in the crate -- only in that binary.
#![allow(dead_code)]

use dom_solana_daemon_route::laboratory;
use dom_solana_daemon_route::registry::{ProvisionedSolanaRegistryV1, SolanaChainFactsV1};
use dom_solana_daemon_route::terms::ProvisionedPositionV1;
use dom_solana_daemon_route::SolanaRouteBootstrapPlanV1;
use kaystra_core::terms::SettlementTermsV1;

pub use laboratory::{
    accounts, downstream_facts, identities, observation, position, upstream_facts,
    DOM_ANCHOR_HEIGHT, DOWNSTREAM_TERMS, NETWORK, NOW_SECONDS, PARTICIPANT_BINDINGS, PARTY_A,
    PARTY_B, RELAY_ROSTER, TIME_EVIDENCE, TIME_POLICY, UPSTREAM_TERMS,
};

/// The laboratory passphrase, as bytes, for callers that hand it to the identity store.
pub const IDENTITY_PASSPHRASE: &[u8] = laboratory::IDENTITY_PASSPHRASE.as_bytes();

pub struct Provisioned {
    pub directory: tempfile::TempDir,
    /// Everything the daemon's layout does not declare: the leg's setup store, the
    /// throwaway time-anchor store the provisioner proves its ladder in.
    pub provisioning: tempfile::TempDir,
    pub plan: SolanaRouteBootstrapPlanV1,
    pub upstream: SettlementTermsV1,
    pub downstream: SettlementTermsV1,
    pub upstream_setup: ProvisionedPositionV1,
    pub downstream_setup: ProvisionedPositionV1,
    pub upstream_facts: SolanaChainFactsV1,
    pub downstream_facts: SolanaChainFactsV1,
    pub registry: ProvisionedSolanaRegistryV1,
    pub dom_chain_id: [u8; 32],
    pub dom_asset_id: [u8; 32],
}

impl Provisioned {
    /// The registry as the daemon resolves it: loaded from the store through the
    /// authenticated bundle, never from the manifest that was handed to the store.
    pub fn resolved_registry(&self) -> deployment_registry::ResolvedRegistryV1 {
        let bytes = std::fs::read(self.directory.path().join(laboratory::REGISTRY_AUTHORITIES))
            .expect("the authority bundle was written");
        let bundle = dom_interopd::ProductionAuthorityBundleV1::decode_canonical(&bytes)
            .expect("the authority bundle decodes");
        deployment_registry::RegistryStoreV1::open_existing(
            &self.directory.path().join(laboratory::REGISTRY_STORE),
        )
        .expect("the registry store opens")
        .load_current(
            bundle.registry(),
            &btc_crypto::SecpContext::new(&[0x5a; 32]),
            deployment_registry::RegistryValidationPolicyV1 {
                now_seconds: NOW_SECONDS,
                expected_network_id: self.registry.network_id,
                minimum_epoch: self.registry.epoch,
            },
        )
        .expect("the registry loads")
        .expect("the store holds a current registry")
    }
}

pub fn provision_all() -> Provisioned {
    let directory = tempfile::tempdir().expect("a private working directory");
    // Separate from the state directory on purpose: neither the leg's setup store nor the
    // ladder check store is a path role of the daemon's layout, and the layout refuses a
    // managed path that already exists.
    let provisioning = tempfile::tempdir().expect("a private provisioning directory");

    // The fixed second, not the clock: a test route has to be reasoned about when it fails.
    // Anything handing the route to the ceremony passes the real clock instead.
    let route = laboratory::provision(directory.path(), provisioning.path(), NOW_SECONDS)
        .expect("the laboratory route provisions");

    Provisioned {
        dom_chain_id: route.registry.dom_chain_id,
        dom_asset_id: route.registry.dom_asset_id,
        upstream: route.upstream.terms.clone(),
        downstream: route.downstream.terms.clone(),
        upstream_setup: route.upstream,
        downstream_setup: route.downstream,
        upstream_facts: route.upstream_facts,
        downstream_facts: route.downstream_facts,
        registry: route.registry,
        plan: route.plan,
        directory,
        provisioning,
    }
}
