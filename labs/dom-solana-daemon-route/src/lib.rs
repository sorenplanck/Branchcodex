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
//! # Why both positions are Solana, and why they are two clusters
//!
//! A daemon route is `counterparty <-> DOM <-> counterparty`: the family enum has
//! no `Dom` variant and the bootstrap carries exactly two legs. A single
//! DOM<->Solana operation is therefore half a route in the daemon's own terms.
//! Filling both positions with Solana is what makes this work independent of the
//! Bitcoin and Monero legs: it exercises the Solana settlement face in both
//! positions and waits for nobody. When another leg is ready, its owner replaces
//! one position and nothing here has to change.
//!
//! The two positions sit on two DIFFERENT clusters, and that is a constraint the
//! daemon imposes rather than a choice made here. `RouteTimePolicyV2::from_registry`
//! refuses a route whose two counterparty legs carry the same chain id:
//!
//! ```text
//! if (!native_dom_xmr_v23
//!     && upstream.counterparty_leg.chain_id == downstream.counterparty_leg.chain_id)
//! ```
//!
//! The one profile that admits a shared counterparty chain is the mainnet DOM/XMR
//! one, and it exists because on Monero the two roles genuinely sit on a single chain
//! -- which is why it carries an extra equality constraint between the two
//! checkpoints to make that safe. A general route's two counterparty positions are
//! two chains. So a Solana route in both directions is `Solana(A) -> DOM -> Solana(B)`:
//! Solana emits into the hub at the upstream position and receives from it at the
//! downstream one, both through the daemon, with no other chain family involved.
//!
//! This also constrains the other legs, and it is worth saying once here: a
//! DOM<->Monero route with both positions on one Monero chain needs the v23 profile,
//! not this one.
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
//! [`SolanaRouteBootstrapPlanV1::artifact_pins_are_complete`] says so in the type.

#![forbid(unsafe_code)]

pub mod declared_inputs;
pub mod owner_only;
pub mod participants;
pub mod registry;
pub mod roster;
pub mod route_time;
pub mod terms;

use std::path::{Path, PathBuf};

use dom_interopd::{
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionChainFamilyV11,
    ProductionConfigErrorV1, ProductionContractsBootstrapPinsV5, ProductionF6PathReferencesV4,
    ProductionF6PathRoleV4, ProductionF6PathRoleV8, ProductionFamilyInputsV5,
    ProductionFamilyInputsV6, ProductionPathReferencesV1, ProductionPathRoleV1,
    ProductionRelayAuthorityPinsV6, ProductionRoutePinsV1, ProductionRuntimeBoundsV1,
    ProductionUniversalBootstrapFieldsV11, ProductionUniversalLegV11,
    PRODUCTION_CREATE_CONFIG_FILE_V11, PRODUCTION_F6_PATH_ROLE_COUNT_V4,
    PRODUCTION_F6_PATH_ROLE_COUNT_V8, PRODUCTION_PATH_ROLE_COUNT_V1,
    PRODUCTION_REOPEN_CONFIG_FILE_V11,
};
use participants::ProvisionedParticipantBindingsV1;
use registry::ProvisionedSolanaRegistryV1;
use roster::ProvisionedRelayRosterV1;
use route_time::ProvisionedRouteTimeV1;
use terms::ProvisionedRouteTermsV1;
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
/// The layout, in `ProductionPathRoleV1::ALL` order.
///
/// The order is load-bearing and silent if wrong: the loader resolves role N to entry
/// N, so a transposed pair would put the upstream terms where the DOM wallet belongs
/// and nothing would say so until authentication failed for an unrelated-looking
/// reason. `the_layout_assigns_every_role_the_path_it_is_named_for` asserts the whole
/// mapping against the loaded layout.
///
/// The last nine roles are `ManagedDirectory`, not files -- the daemon creates
/// directories there -- so they are named as directories. Naming one `.sqlite3` would
/// describe a database that never exists.
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
    "state/relay/queue.v1",
    "state/relay/upstream-sender.v1",
    "state/relay/upstream-inbox.v1",
    "state/relay/upstream-frames.v1",
    "state/contracts/upstream.v1",
    "state/relay/downstream-sender.v1",
    "state/relay/downstream-inbox.v1",
    "state/relay/downstream-frames.v1",
    "state/contracts/downstream.v1",
];

/// The eleven F6 V4 roles.
/// The eleven F6 V4 leaves, in `ProductionF6PathRoleV4::ALL` order.
///
/// Six of these were previously named for other roles: the order runs
/// upstream-book and upstream-attestation BEFORE the downstream binding log, not
/// after it. Every one is a managed file, so the daemon created whatever path the
/// role pointed at and nothing failed -- an operator reading
/// `upstream-observation` would have been looking at the downstream binding log.
/// `the_layout_assigns_every_role_the_path_it_is_named_for` now asserts the mapping.
const F6_V4_PATHS: [&str; PRODUCTION_F6_PATH_ROLE_COUNT_V4] = [
    "state/f6/solver-status.v1.sqlite3",
    "state/f6/upstream-pre-f6-time.v1.sqlite3",
    "state/f6/downstream-pre-f6-time.v1.sqlite3",
    "state/f6/upstream-binding-log.v1.sqlite3",
    "state/f6/upstream-receipts.v1.sqlite3",
    "state/f6/upstream-candidate-book.v1.sqlite3",
    "state/f6/upstream-candidate-attestation.v1.sqlite3",
    "state/f6/downstream-binding-log.v1.sqlite3",
    "state/f6/downstream-receipts.v1.sqlite3",
    "state/f6/downstream-candidate-book.v1.sqlite3",
    "state/f6/downstream-candidate-attestation.v1.sqlite3",
];

/// The seven F6 V8 roles the universal family adds.
/// The seven F6 V8 leaves, in `ProductionF6PathRoleV8::ALL` order.
///
/// `AuthorityBundleV7` is role SIX, the last, and it is the only `InputFile` among
/// them. This list had it first, which would have made the loader demand an input
/// file at the claim-lineage path and demand the bundle's own path be absent -- and
/// it would have said `InputArtifactUnavailable` about a path no one had written,
/// naming nothing about the real cause.
const F6_V8_PATHS: [&str; PRODUCTION_F6_PATH_ROLE_COUNT_V8] = [
    "state/f6/v8-upstream-status.v1.sqlite3",
    "state/f6/v8-downstream-status.v1.sqlite3",
    "state/f6/v8-upstream-time.v1.sqlite3",
    "state/f6/v8-downstream-time.v1.sqlite3",
    "state/f6/v8-upstream-candidate.v1.sqlite3",
    "state/f6/v8-downstream-candidate.v1.sqlite3",
    "artifacts/f6/authority-bundle.v8",
];

/// The Contracts transport identity authority.
///
/// A DIRECTORY, and one the layout requires to exist in create and in reopen alike --
/// "provisioned outside the daemon, never created and never repaired here". It was
/// named `.sqlite3`, which describes a database the daemon never opens.
const CONTRACTS_IDENTITY_STORE: &str = "state/contracts/transport-identity.v1";
const CONTRACTS_BUDGET_POLICY: &str = "artifacts/contracts-budget-policy.v1";
const CONTRACTS_BOOTSTRAP: &str = "artifacts/contracts-bootstrap.v1";

/// How many of the nineteen route pins are digests of an artifact this crate writes.
///
/// The other six are declarations; see
/// [`SolanaRouteBootstrapPlanV1::artifact_pins_are_complete`].
pub const ARTIFACT_PIN_COUNT: usize = 13;

/// The six pins that are identities a deployment declares rather than digests of
/// artifacts.
///
/// Grouped so a caller supplies them together and the type says what they are. Every
/// one must be non-zero: `ProductionRoutePinsV1::validate` refuses a zero pin, which is
/// the right refusal -- a zero owner id would fence nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteIdentitiesV1 {
    /// Composed route identity. Threaded into admission by the caller and checked for
    /// consistency against the route store's checkpoint; never derived from content.
    pub route_id: [u8; 32],
    /// The identity a fenced store records as its owner, so another process is refused.
    pub process_owner_id: [u8; 32],
    /// The settlement coordinator this route's work is dispatched under.
    pub coordinator_id: [u8; 32],
    /// The plan authority the coordinator accepts plans from.
    pub coordinator_plan_authority_id: [u8; 32],
    /// Binds the concrete actuator authorities.
    pub actuator_bindings_digest: [u8; 32],
    /// Binds the solver inventory and bond authority.
    pub solver_inventory_binding_digest: [u8; 32],
}

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
    /// The registry, once it has been provisioned. Present means four pins are
    /// measurements of an artifact on disk instead of derived labels.
    pub registry: Option<ProvisionedSolanaRegistryV1>,
    /// The two frozen terms, once both positions have been established. Present
    /// means the route names its counterparty chain in the place the daemon reads it
    /// from, which is what makes the positions resolvable as Solana at all.
    pub terms: Option<ProvisionedRouteTermsV1>,
    /// The Relay roster, once both positions have one. Present means the daemon can
    /// tell which key speaks for which participant of which position.
    pub roster: Option<ProvisionedRelayRosterV1>,
    /// The two Solana setups, once both positions have been established. Present
    /// means the route carries the DLEQ the daemon authenticates each position with.
    pub participants: Option<ProvisionedParticipantBindingsV1>,
    /// The signed time policy and its evidence, once both exist. Present means the
    /// route has a time authority: the daemon can tell whether a deadline is still
    /// reachable instead of trusting a clock.
    pub route_time: Option<ProvisionedRouteTimeV1>,
    /// The six declared identities, once a caller has supplied them. Absent means the
    /// plan is using derived laboratory labels.
    pub identities: Option<RouteIdentitiesV1>,
    /// Digest of the F6 authority bundle, once one has been written. It is not one of
    /// the nineteen route pins -- it is a field of the universal V11 configuration --
    /// but `authenticate_f6_bundle_file_v8` compares it with the file's own digest, so
    /// it is a measurement of an artifact exactly like the other thirteen.
    pub f6_authority_bundle: Option<[u8; 32]>,
}

impl SolanaRouteBootstrapPlanV1 {
    /// A route with a Solana position on both sides of the DOM hub.
    ///
    /// The two positions differ in every identifier the daemon checks, and they sit on
    /// two DIFFERENT clusters. That is not a preference:
    /// `RouteTimePolicyV2::from_registry` refuses a route whose two counterparty legs
    /// carry the same chain id unless the DOM/XMR mainnet profile is selected, and
    /// that profile exists because on Monero the two roles genuinely share one chain.
    /// A general route's two counterparty positions are two chains, so a Solana route
    /// in both directions is `Solana(A) -> DOM -> Solana(B)`: Solana emits at one end
    /// and receives at the other, both through the hub.
    pub fn both_positions_on_solana(
        upstream_genesis: [u8; 32],
        downstream_genesis: [u8; 32],
    ) -> Self {
        Self {
            network_id: placeholder("network-id"),
            route_id: placeholder("route-id"),
            upstream: SolanaRoutePositionPlanV1 {
                settlement_id: placeholder("upstream-settlement-id"),
                session_id: placeholder("upstream-session-id"),
                chain_id: upstream_genesis,
            },
            downstream: SolanaRoutePositionPlanV1 {
                settlement_id: placeholder("downstream-settlement-id"),
                session_id: placeholder("downstream-session-id"),
                chain_id: downstream_genesis,
            },
            registry: None,
            terms: None,
            roster: None,
            participants: None,
            route_time: None,
            identities: None,
            f6_authority_bundle: None,
        }
    }

    /// Bind a provisioned registry, so the pins it determines stop being labels.
    ///
    /// The network id comes from the registry once one exists: every other artifact
    /// is bound to that id, and a plan keeping its own would describe a different
    /// interop network than the registry it points at.
    pub fn with_registry(mut self, provisioned: ProvisionedSolanaRegistryV1) -> Self {
        self.network_id = provisioned.network_id;
        self.registry = Some(provisioned);
        self
    }

    /// Bind the two provisioned terms, so the three pins they determine stop being
    /// labels.
    ///
    /// `route_scope_digest` is taken from the pair rather than recomputed here: the
    /// time authority signs a scope over both canonical terms in position order, and
    /// a scope derived from anything else names a different route.
    pub fn with_terms(mut self, provisioned: ProvisionedRouteTermsV1) -> Self {
        self.terms = Some(provisioned);
        self
    }

    /// Bind the provisioned Relay roster, so `relay_binding_digest` stops being a
    /// label.
    pub fn with_roster(mut self, provisioned: ProvisionedRelayRosterV1) -> Self {
        self.roster = Some(provisioned);
        self
    }

    /// Bind the provisioned participant bindings, so `participant_bindings_digest`
    /// stops being a label.
    pub fn with_participants(mut self, provisioned: ProvisionedParticipantBindingsV1) -> Self {
        self.participants = Some(provisioned);
        self
    }

    /// Bind the provisioned time policy and evidence, so the four pins they determine
    /// stop being labels.
    pub fn with_route_time(mut self, provisioned: ProvisionedRouteTimeV1) -> Self {
        self.route_time = Some(provisioned);
        self
    }

    /// How many of the nineteen route pins are measurements of a real artifact.
    ///
    /// Reported as a number rather than a boolean because the bootstrap is built
    /// one artifact at a time and "some are real" is not a useful thing to know.
    pub const fn measured_pin_count(&self) -> usize {
        let registry = match self.registry {
            // network_id, registry_manifest_digest, registry_minimum_epoch and
            // registry_authority_set_digest.
            Some(_) => 4,
            None => 0,
        };
        let terms = match self.terms {
            // upstream_terms_digest, downstream_terms_digest and route_scope_digest.
            Some(_) => 3,
            None => 0,
        };
        let roster = match self.roster {
            // relay_binding_digest.
            Some(_) => 1,
            None => 0,
        };
        let participants = match self.participants {
            // participant_bindings_digest.
            Some(_) => 1,
            None => 0,
        };
        let route_time = match self.route_time {
            // The two authority-set digests, the policy digest and the evidence digest.
            Some(_) => 4,
            None => 0,
        };
        registry + terms + roster + participants + route_time
    }

    /// True while any ARTIFACT pin is still a derived label rather than the digest of
    /// something on disk. While it holds, the manifest encodes and decodes but
    /// authentication would refuse the route, because authentication reads the
    /// artifacts.
    ///
    /// The threshold is [`ARTIFACT_PIN_COUNT`] and not nineteen, and the difference is
    /// not bookkeeping. Six of the nineteen pins are not digests of artifacts at all:
    /// they are identities a deployment DECLARES, and nothing in
    /// `load_authenticated_production_inputs_v1` compares them with a file. Reading the
    /// daemon's own uses of them says so plainly -- `process_owner_id` is the fence
    /// owner written into the route store it creates, `coordinator_id` and
    /// `coordinator_plan_authority_id` are handed to the coordinator at run time,
    /// `route_id` is threaded into admission by the caller and only ever checked for
    /// consistency against the stored checkpoint, and the two binding digests appear in
    /// the pins' own non-zero validation and in the run-time signer binding. Counting
    /// them as missing artifacts would mean this crate could never report itself
    /// complete no matter what it wrote.
    pub const fn artifact_pins_are_complete(&self) -> bool {
        self.measured_pin_count() >= ARTIFACT_PIN_COUNT
    }

    /// Declare the six identity pins.
    ///
    /// Without this the plan derives them from labels, which is honest for a laboratory
    /// and wrong for a deployment: `process_owner_id` in particular is the identity a
    /// fenced store will refuse another process for, so it belongs to whoever runs the
    /// daemon and not to whoever wrote the manifest.
    /// Bind the digest of the F6 authority bundle that was written.
    pub fn with_f6_authority_bundle(mut self, digest: [u8; 32]) -> Self {
        self.f6_authority_bundle = Some(digest);
        self
    }

    /// True once the F6 authority bundle on disk and the digest the manifest declares
    /// are the same measurement.
    pub const fn f6_authority_bundle_is_measured(&self) -> bool {
        self.f6_authority_bundle.is_some()
    }

    /// Every relative path this layout declares, in role order: the twenty-eight V1
    /// roles, then the eleven F6 V4 roles, then the seven F6 V8 roles.
    ///
    /// Exposed so a caller can create the parent directories the loader walks, and so a
    /// test can assert the role-to-path mapping against the loaded layout rather than
    /// trusting that two lists were written in the same order.
    pub fn path_relatives() -> Vec<&'static str> {
        BASE_PATHS
            .iter()
            .chain(F6_V4_PATHS.iter())
            .chain(F6_V8_PATHS.iter())
            .copied()
            .collect()
    }

    /// The layout's own relative path for one V1 role.
    ///
    /// Resolved through `ProductionPathRoleV1::ALL` rather than by a hard-coded index,
    /// because a positional assumption about these lists is exactly what went wrong in
    /// the F6 ones.
    pub fn relative(role: ProductionPathRoleV1) -> &'static str {
        BASE_PATHS[Self::position(&ProductionPathRoleV1::ALL, role)]
    }

    /// The layout's own relative path for one F6 V4 role.
    pub fn f6_v4_relative(role: ProductionF6PathRoleV4) -> &'static str {
        F6_V4_PATHS[Self::position(&ProductionF6PathRoleV4::ALL, role)]
    }

    /// The layout's own relative path for the Contracts transport identity directory.
    pub const fn contracts_transport_identity_relative() -> &'static str {
        CONTRACTS_IDENTITY_STORE
    }

    /// The layout's own relative path for the Contracts budget policy.
    pub const fn contracts_budget_policy_relative() -> &'static str {
        CONTRACTS_BUDGET_POLICY
    }

    /// The layout's own relative path for the Contracts bootstrap artifact.
    pub const fn contracts_bootstrap_relative() -> &'static str {
        CONTRACTS_BOOTSTRAP
    }

    /// The layout's own relative path for one F6 V8 role.
    ///
    /// `ProductionF6PathRoleV8::AuthorityBundleV7` is the only input file among them.
    pub fn f6_v8_relative(role: ProductionF6PathRoleV8) -> &'static str {
        F6_V8_PATHS[Self::position(&ProductionF6PathRoleV8::ALL, role)]
    }

    fn position<T: PartialEq>(all: &[T], role: T) -> usize {
        all.iter()
            .position(|candidate| *candidate == role)
            .expect("every role appears in its own ALL")
    }

    pub fn with_identities(mut self, identities: RouteIdentitiesV1) -> Self {
        self.route_id = identities.route_id;
        self.identities = Some(identities);
        self
    }

    fn pins(&self) -> ProductionRoutePinsV1 {
        // Measured where an artifact exists, derived where one does not yet.
        let (manifest_digest, minimum_epoch, authority_set_digest) = match &self.registry {
            Some(provisioned) => (
                provisioned.manifest_digest,
                provisioned.epoch,
                provisioned.authority_set_digest,
            ),
            None => (
                placeholder("registry-manifest"),
                1,
                placeholder("registry-authority-set"),
            ),
        };
        let (upstream_terms, downstream_terms, route_scope) = match &self.terms {
            Some(provisioned) => (
                provisioned.upstream_terms_digest,
                provisioned.downstream_terms_digest,
                provisioned.route_scope_digest,
            ),
            None => (
                placeholder("upstream-terms"),
                placeholder("downstream-terms"),
                placeholder("route-scope"),
            ),
        };
        let time = self.route_time;
        let identities = self.identities;
        ProductionRoutePinsV1 {
            network_id: self.network_id,
            route_id: self.route_id,
            registry_manifest_digest: manifest_digest,
            registry_minimum_epoch: minimum_epoch,
            registry_authority_set_digest: authority_set_digest,
            time_policy_authority_set_digest: time
                .map_or_else(|| placeholder("time-policy-authority-set"), |value| {
                    value.time_policy_authority_set_digest
                }),
            time_evidence_authority_set_digest: time
                .map_or_else(|| placeholder("time-evidence-authority-set"), |value| {
                    value.time_evidence_authority_set_digest
                }),
            upstream_terms_digest: upstream_terms,
            downstream_terms_digest: downstream_terms,
            route_scope_digest: route_scope,
            participant_bindings_digest: match &self.participants {
                Some(provisioned) => provisioned.participant_bindings_digest,
                None => placeholder("participant-bindings"),
            },
            relay_binding_digest: match &self.roster {
                Some(provisioned) => provisioned.relay_binding_digest,
                None => placeholder("relay-binding"),
            },
            time_policy_digest: time
                .map_or_else(|| placeholder("time-policy"), |value| value.time_policy_digest),
            time_evidence_digest: time.map_or_else(
                || placeholder("time-evidence"),
                |value| value.time_evidence_digest,
            ),
            process_owner_id: identities
                .map_or_else(|| placeholder("process-owner"), |value| value.process_owner_id),
            coordinator_id: identities
                .map_or_else(|| placeholder("coordinator"), |value| value.coordinator_id),
            coordinator_plan_authority_id: identities.map_or_else(
                || placeholder("coordinator-plan-authority"),
                |value| value.coordinator_plan_authority_id,
            ),
            actuator_bindings_digest: identities.map_or_else(
                || placeholder("actuator-bindings"),
                |value| value.actuator_bindings_digest,
            ),
            solver_inventory_binding_digest: identities.map_or_else(
                || placeholder("solver-inventory-binding"),
                |value| value.solver_inventory_binding_digest,
            ),
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
            f6_authority_bundle_digest: self
                .f6_authority_bundle
                .unwrap_or_else(|| placeholder("f6-authority-bundle")),
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
        // The loader validates the directory it reads from, not the one a caller meant
        // to create: owner-only, or the whole bootstrap is refused before any pin is
        // compared.
        owner_only::directory(state_dir)
            .map_err(|_| ProductionConfigErrorV1::InputArtifactUnavailable)?;
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
            owner_only::write(&path, &bytes)
                .map_err(|_| ProductionConfigErrorV1::InputArtifactUnavailable)?;
            written.push(path);
        }
        written
            .try_into()
            .map_err(|_| ProductionConfigErrorV1::InputArtifactUnavailable)
    }
}
