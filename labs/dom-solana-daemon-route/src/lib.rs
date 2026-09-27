//! Bootstrap provisioning for a DOM daemon route whose counterparty positions
//! are Solana.
//!
//! # Why this exists
//!
//! The daemon already supports a Solana leg everywhere it matters:
//! `ProductionChainFamilyV11::Sol` is one of its four chain families, the
//! deployment registry encodes a Solana deployment, `solana_session(leg)` is
//! populated by the authenticated inputs, `production_child_solana` is the
//! settlement face, and the Solana actuator store has a pinned name the daemon
//! creates for a route whose admitted shape carries a Solana leg.
//!
//! What does not exist anywhere in the tree is a provisioner. Every writer of a
//! V11 bootstrap manifest is `cfg(test)` code, there is no
//! `bootstrap-create-*.conf` committed, and `deploy-genconfig` -- which does
//! generate the registry and its authority set -- has no Solana path. So a route
//! cannot be handed to the daemon without one, for any chain. This crate is that
//! provisioner for the Solana positions.
//!
//! # Why both positions are Solana
//!
//! A daemon route is `counterparty <-> DOM <-> counterparty`: the family enum has
//! no `Dom` variant and the bootstrap carries exactly two legs. A single
//! DOM<->Solana operation is therefore half a route in the daemon's own terms.
//! Filling both positions with Solana is what makes this work independent of the
//! Bitcoin and Monero legs: it exercises the Solana settlement face in both
//! positions and waits for nobody. When another leg is ready, its owner replaces
//! one position and nothing here has to change.
//!
//! # What the bytes are, and what they are not
//!
//! The manifest is produced by the daemon's own encoder, reached through public
//! constructors: `from_parts_v6` builds the common family, then
//! `from_common_v6_and_legs_v11` adds the two Solana positions, then
//! `canonical_bytes()` emits the canonical form. Nothing here formats a manifest
//! by hand, which is the discipline `deploy-genconfig` states for the registry and
//! is worth keeping for the manifest too.
//!
//! The pins are another matter and this crate is explicit about it. A pin in
//! `ProductionRoutePinsV1` is the digest of an artifact, and a pin only means
//! something once the artifact exists and hashes to it. [`SolanaRouteBootstrapPlanV1`]
//! derives its pins deterministically from labels so a manifest can be built,
//! encoded and decoded before any artifact is signed. A manifest built this way is
//! structurally valid and **not** a route the daemon would admit: authentication
//! reads the artifacts. Producing them is the next step, and
//! [`SolanaRouteBootstrapPlanV1::pins_are_placeholders`] says so in the type.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use dom_interopd::{
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionChainFamilyV11,
    ProductionConfigErrorV1, ProductionContractsBootstrapPinsV5, ProductionF6PathReferencesV4,
    ProductionFamilyInputsV5, ProductionFamilyInputsV6, ProductionPathReferencesV1,
    ProductionRelayAuthorityPinsV6, ProductionRoutePinsV1, ProductionRuntimeBoundsV1,
    ProductionUniversalBootstrapFieldsV11, ProductionUniversalLegV11,
    PRODUCTION_CREATE_CONFIG_FILE_V11, PRODUCTION_F6_PATH_ROLE_COUNT_V4,
    PRODUCTION_F6_PATH_ROLE_COUNT_V8, PRODUCTION_PATH_ROLE_COUNT_V1,
    PRODUCTION_REOPEN_CONFIG_FILE_V11,
};
use sha2::{Digest, Sha256};

/// Domain for every derived placeholder digest, so a value from this crate can
/// never be mistaken for a measurement of a real artifact.
const PLACEHOLDER_DOMAIN: &[u8] = b"DOM-SOLANA-DAEMON-ROUTE/PLACEHOLDER-PIN/V1\0";

/// A deterministic, nonzero, label-distinct digest.
///
/// Deterministic so two runs produce the same manifest; label-distinct because the
/// daemon refuses several of these fields for being equal to each other, and a
/// refusal caused by two placeholders colliding would say nothing about the route.
fn placeholder(label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PLACEHOLDER_DOMAIN);
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

/// The 28 base path roles, in the order `ProductionPathRoleV1` declares them.
/// Names are relative and distinct; path isolation across the whole set is what
/// the daemon validates, so every name in this crate appears exactly once.
const BASE_PATHS: [&str; PRODUCTION_PATH_ROLE_COUNT_V1] = [
    "artifacts/registry.v1.sqlite3",
    "artifacts/registry-authorities.v1",
    "artifacts/upstream-terms.v1",
    "artifacts/downstream-terms.v1",
    "artifacts/participant-bindings.v1",
    "artifacts/relay-roster.v1",
    "artifacts/time-policy.v1",
    "artifacts/time-evidence.v1",
    "state/dom-wallet",
    "state/route.v1.sqlite3",
    "state/time-anchor.v1.sqlite3",
    "state/coordinator.v1.sqlite3",
    "state/dom-actuator.v1.sqlite3",
    "state/evm-actuator.v1.sqlite3",
    "state/bitcoin-actuator.v1.sqlite3",
    "state/bitcoin-participant.v1.sqlite3",
    "state/dom-upstream-participant.v1.sqlite3",
    "state/dom-downstream-participant.v1.sqlite3",
    "state/solver-inventory.v1.sqlite3",
    "state/relay-queue.v1.sqlite3",
    "state/upstream-relay-sender.v1.sqlite3",
    "state/upstream-relay-inbox.v1.sqlite3",
    "state/upstream-relay-frames.v1.sqlite3",
    "state/upstream-contracts.v1.sqlite3",
    "state/downstream-relay-sender.v1.sqlite3",
    "state/downstream-relay-inbox.v1.sqlite3",
    "state/downstream-relay-frames.v1.sqlite3",
    "state/downstream-contracts.v1.sqlite3",
];

/// The eleven F6 V4 roles.
const F6_V4_PATHS: [&str; PRODUCTION_F6_PATH_ROLE_COUNT_V4] = [
    "state/f6/solver-status.v1.sqlite3",
    "state/f6/upstream-pre-f6-time.v1.sqlite3",
    "state/f6/downstream-pre-f6-time.v1.sqlite3",
    "state/f6/upstream-binding-log.v1.sqlite3",
    "state/f6/upstream-receipts.v1.sqlite3",
    "state/f6/downstream-binding-log.v1.sqlite3",
    "state/f6/downstream-receipts.v1.sqlite3",
    "state/f6/upstream-observation.v1.sqlite3",
    "state/f6/downstream-observation.v1.sqlite3",
    "state/f6/upstream-exposure.v1.sqlite3",
    "state/f6/downstream-exposure.v1.sqlite3",
];

/// The seven F6 V8 roles the universal family adds.
const F6_V8_PATHS: [&str; PRODUCTION_F6_PATH_ROLE_COUNT_V8] = [
    "artifacts/f6/authority-bundle.v8",
    "state/f6/v8-upstream-admission.v1.sqlite3",
    "state/f6/v8-downstream-admission.v1.sqlite3",
    "state/f6/v8-upstream-exposure.v1.sqlite3",
    "state/f6/v8-downstream-exposure.v1.sqlite3",
    "state/f6/v8-refund-arming.v1.sqlite3",
    "state/f6/v8-claim-lineage.v1.sqlite3",
];

const CONTRACTS_IDENTITY_STORE: &str = "state/contracts-transport-identity.v1.sqlite3";
const CONTRACTS_BUDGET_POLICY: &str = "artifacts/contracts-budget-policy.v1";
const CONTRACTS_BOOTSTRAP: &str = "artifacts/contracts-bootstrap.v1";

/// One counterparty position of the route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolanaRoutePositionPlanV1 {
    /// Exact settlement bound by this position.
    pub settlement_id: [u8; 32],
    /// Exact signing session bound by this position; never the settlement id,
    /// which the daemon refuses.
    pub session_id: [u8; 32],
    /// The Solana cluster's own identity. On a live cluster this is its genesis
    /// hash, which is what makes the position specific to one cluster.
    pub chain_id: [u8; 32],
}

/// Everything a caller chooses about the route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolanaRouteBootstrapPlanV1 {
    pub network_id: [u8; 32],
    pub route_id: [u8; 32],
    pub upstream: SolanaRoutePositionPlanV1,
    pub downstream: SolanaRoutePositionPlanV1,
}

impl SolanaRouteBootstrapPlanV1 {
    /// A route with a Solana position on both sides of the DOM hub, for one
    /// cluster.
    ///
    /// The two positions differ in every identifier the daemon checks, because a
    /// route is two distinct settlements even when both sit on the same cluster.
    pub fn both_positions_on_cluster(cluster_genesis: [u8; 32]) -> Self {
        Self {
            network_id: placeholder("network-id"),
            route_id: placeholder("route-id"),
            upstream: SolanaRoutePositionPlanV1 {
                settlement_id: placeholder("upstream-settlement-id"),
                session_id: placeholder("upstream-session-id"),
                chain_id: cluster_genesis,
            },
            downstream: SolanaRoutePositionPlanV1 {
                settlement_id: placeholder("downstream-settlement-id"),
                session_id: placeholder("downstream-session-id"),
                chain_id: cluster_genesis,
            },
        }
    }

    /// True for every plan this crate can build today: the pins below are derived
    /// labels, not digests of signed artifacts, so the manifest encodes and decodes
    /// but authentication would refuse it. Kept as a method rather than a comment
    /// so a caller cannot pretend otherwise.
    pub const fn pins_are_placeholders(&self) -> bool {
        true
    }

    fn pins(&self) -> ProductionRoutePinsV1 {
        ProductionRoutePinsV1 {
            network_id: self.network_id,
            route_id: self.route_id,
            registry_manifest_digest: placeholder("registry-manifest"),
            registry_minimum_epoch: 1,
            registry_authority_set_digest: placeholder("registry-authority-set"),
            time_policy_authority_set_digest: placeholder("time-policy-authority-set"),
            time_evidence_authority_set_digest: placeholder("time-evidence-authority-set"),
            upstream_terms_digest: placeholder("upstream-terms"),
            downstream_terms_digest: placeholder("downstream-terms"),
            route_scope_digest: placeholder("route-scope"),
            participant_bindings_digest: placeholder("participant-bindings"),
            relay_binding_digest: placeholder("relay-binding"),
            time_policy_digest: placeholder("time-policy"),
            time_evidence_digest: placeholder("time-evidence"),
            process_owner_id: placeholder("process-owner"),
            coordinator_id: placeholder("coordinator"),
            coordinator_plan_authority_id: placeholder("coordinator-plan-authority"),
            actuator_bindings_digest: placeholder("actuator-bindings"),
            solver_inventory_binding_digest: placeholder("solver-inventory-binding"),
        }
    }

    /// Bounds chosen to satisfy the daemon's own rules rather than tuned: this
    /// crate provisions a route, it does not decide a deployment's timing policy.
    ///
    /// The rules are a chain of inequalities, and the first attempt at this
    /// function broke four of them at once. They are written out so an edit has to
    /// look at them:
    ///
    /// * `60_000 <= lease_duration <= 600_000`;
    /// * `0 < renew_before < lease_duration`;
    /// * `0 < dispatch_lease <= renew_before`  -- a dispatch lease may not outlive
    ///   the moment the owner must renew by;
    /// * `dispatch_lease <= coordinator_lease <= 600_000`, same for the actuator;
    /// * `1_000 <= external_call_timeout <= 60_000` AND
    ///   `external_call_timeout <= dispatch_lease` -- an external call may not
    ///   outlast the lease that authorises it;
    /// * `recovery_backoff <= waiting_backoff` and `relay_poll <= waiting_backoff`;
    /// * every backoff within `[10, 30_000]` and no larger than
    ///   `lease_duration - renew_before`, the interval it is safe to sleep for;
    /// * `per_queue_batch_limit == 1` exactly -- the driver is structurally
    ///   single-action and says so.
    fn bounds() -> ProductionRuntimeBoundsV1 {
        ProductionRuntimeBoundsV1 {
            lease_duration_ms: 120_000,
            renew_before_ms: 60_000,
            dispatch_lease_ms: 60_000,
            coordinator_lease_ms: 120_000,
            actuator_lease_ms: 120_000,
            external_call_timeout_ms: 30_000,
            waiting_backoff_ms: 5_000,
            recovery_backoff_ms: 5_000,
            relay_poll_backoff_ms: 1_000,
            per_queue_batch_limit: 1,
        }
    }

    fn relay_pins() -> ProductionRelayAuthorityPinsV6 {
        ProductionRelayAuthorityPinsV6 {
            relay_database_id: placeholder("relay-database"),
            upstream_sender_store_id: placeholder("upstream-sender-store"),
            upstream_inbox_id: placeholder("upstream-inbox"),
            upstream_reassembler_id: placeholder("upstream-reassembler"),
            downstream_sender_store_id: placeholder("downstream-sender-store"),
            downstream_inbox_id: placeholder("downstream-inbox"),
            downstream_reassembler_id: placeholder("downstream-reassembler"),
            relay_max_envelopes: 1_024,
            sender_max_envelopes: 1_024,
            inbox_max_entries: 1_024,
            frame_max_messages: 256,
            frame_max_active_bytes: 1 << 20,
            frame_max_active_chunks: 1_024,
        }
    }

    fn legs(&self) -> [ProductionUniversalLegV11; 2] {
        [
            ProductionUniversalLegV11 {
                family: ProductionChainFamilyV11::Sol,
                settlement_id: self.upstream.settlement_id,
                session_id: self.upstream.session_id,
                chain_id: self.upstream.chain_id,
                actuator_store: "state/upstream/solana-actuator.v1.sqlite3".to_owned(),
                authority_bundle: "artifacts/upstream-solana-authority-bundle.v1".to_owned(),
                authority_bundle_digest: placeholder("upstream-solana-authority-bundle"),
            },
            ProductionUniversalLegV11 {
                family: ProductionChainFamilyV11::Sol,
                settlement_id: self.downstream.settlement_id,
                session_id: self.downstream.session_id,
                chain_id: self.downstream.chain_id,
                actuator_store: "state/downstream/solana-actuator.v1.sqlite3".to_owned(),
                authority_bundle: "artifacts/downstream-solana-authority-bundle.v1".to_owned(),
                authority_bundle_digest: placeholder("downstream-solana-authority-bundle"),
            },
        ]
    }

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// The common V6 family for one mode.
    fn common(&self, mode: ProductionBootstrapModeV1) -> Result<ProductionBootstrapConfigV1, ProductionConfigErrorV1> {
        let base: [String; PRODUCTION_PATH_ROLE_COUNT_V1] = Self::owned(&BASE_PATHS)
            .try_into()
            .map_err(|_| ProductionConfigErrorV1::InvalidPathReference)?;
        let f6_v4: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V4] = Self::owned(&F6_V4_PATHS)
            .try_into()
            .map_err(|_| ProductionConfigErrorV1::InvalidPathReference)?;
        let inputs = ProductionFamilyInputsV6::new(
            ProductionFamilyInputsV5::new(
                CONTRACTS_IDENTITY_STORE.to_owned(),
                CONTRACTS_BUDGET_POLICY.to_owned(),
                ProductionF6PathReferencesV4::from_ordered(f6_v4)?,
                CONTRACTS_BOOTSTRAP.to_owned(),
                ProductionContractsBootstrapPinsV5::new(
                    placeholder("contracts-commit-stage"),
                    placeholder("contracts-reveal-stage"),
                )?,
            ),
            Self::relay_pins(),
        );
        ProductionBootstrapConfigV1::from_parts_v6(
            mode,
            self.pins(),
            Self::bounds(),
            ProductionPathReferencesV1::from_ordered(base)?,
            inputs,
        )
    }

    /// The universal V11 fields, carrying both Solana positions.
    fn fields(&self) -> Result<ProductionUniversalBootstrapFieldsV11, ProductionConfigErrorV1> {
        let f6_paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V8] = Self::owned(&F6_V8_PATHS)
            .try_into()
            .map_err(|_| ProductionConfigErrorV1::InvalidPathReference)?;
        Ok(ProductionUniversalBootstrapFieldsV11 {
            f6_paths,
            f6_authority_bundle_digest: placeholder("f6-authority-bundle"),
            refund_arming_authority_epoch: 1,
            remote_relay_database_ids: [
                placeholder("upstream-remote-relay-database"),
                placeholder("downstream-remote-relay-database"),
            ],
            shared_relay_peer_v23: false,
            legs: self.legs(),
        })
    }

    /// The complete V11 configuration for one mode.
    pub fn config(
        &self,
        mode: ProductionBootstrapModeV1,
    ) -> Result<ProductionBootstrapConfigV1, ProductionConfigErrorV1> {
        ProductionBootstrapConfigV1::from_common_v6_and_legs_v11(self.common(mode)?, self.fields()?)
    }

    /// Write both manifests a V11 state directory needs, with the daemon's own
    /// canonical encoding. Returns their paths, create first.
    ///
    /// The two manifests must describe the same route and differ only in mode;
    /// the loader refuses a pair that does not, so they are produced from the same
    /// plan rather than edited into agreement.
    pub fn write_manifests(&self, state_dir: &Path) -> Result<[PathBuf; 2], ProductionConfigErrorV1> {
        let mut written = Vec::with_capacity(2);
        for (mode, name) in [
            (
                ProductionBootstrapModeV1::Create,
                PRODUCTION_CREATE_CONFIG_FILE_V11,
            ),
            (
                ProductionBootstrapModeV1::ReopenExisting,
                PRODUCTION_REOPEN_CONFIG_FILE_V11,
            ),
        ] {
            let bytes = self.config(mode)?.canonical_bytes()?;
            let path = state_dir.join(name);
            std::fs::write(&path, &bytes)
                .map_err(|_| ProductionConfigErrorV1::InputArtifactUnavailable)?;
            written.push(path);
        }
        written
            .try_into()
            .map_err(|_| ProductionConfigErrorV1::InputArtifactUnavailable)
    }
}
