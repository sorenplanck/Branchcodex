//! Native-height deadline consumers. Heights never become Unix timestamps.
//!
//! RPC quorum/identity is the configured trust boundary, not an independent
//! proof-of-work verifier. A privately issued result permits RecoveryOnly,
//! never funding, a secret, an economic finality event, or a refund signature.
use super::{AuthorityRefusalV1 as Error, ZERO_DIGEST};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use chain_profile::{ChainKindV1, MoneroNetworkV1};
use deployment_registry::ResolvedMoneroDeploymentV1;
use kaystra_core::types::TimelockSpec;
use route_composer::ComposedBindingV2;
use route_executor::{Digest32, EventIdV1, FrozenBindingsV1, LegIdV1, RouteIdV1};
use std::{collections::BTreeSet, time::Duration};
use xmr_observer::{CanonicalTip, HttpXmrRpc, XmrNetwork, XmrObserverError, XmrRpcPool};
use xmr_setup_profile::XmrAdapterProfileV1;

pub(super) fn composition_has_height_deadline(composition: &ComposedBindingV2) -> bool {
    [composition.upstream(), composition.downstream()]
        .into_iter()
        .any(|terms| {
            [terms.dom_leg, terms.counterparty_leg]
                .into_iter()
                .any(|leg| matches!(leg.deadline, TimelockSpec::BlockHeight { value } if value > 0))
        })
}

pub(super) fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, Error> {
    let mut hash = Blake2bVar::new(32).map_err(|_| Error::Inconsistent)?;
    hash.update(domain);
    for part in parts {
        hash.update(&(u64::try_from(part.len()).map_err(|_| Error::Inconsistent)?).to_be_bytes());
        hash.update(part);
    }
    let mut digest = ZERO_DIGEST;
    hash.finalize_variable(&mut digest)
        .map_err(|_| Error::Inconsistent)?;
    if digest == ZERO_DIGEST {
        return Err(Error::Inconsistent);
    }
    Ok(digest)
}

#[derive(Clone)]
struct HeightBinding {
    leg: LegIdV1,
    chain_id: Digest32,
    adapter_profile: Digest32,
    dom: bool,
    height: u64,
    context: Digest32,
}

/// Move-only capability issued exclusively after the native observer passes.
pub(crate) struct ProductionDeadlineRecoveryV23 {
    route_id: RouteIdV1,
    frozen: FrozenBindingsV1,
    event_id: EventIdV1,
    reason_digest: Digest32,
}

impl ProductionDeadlineRecoveryV23 {
    pub(crate) const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }
    pub(crate) const fn frozen_bindings(&self) -> &FrozenBindingsV1 {
        &self.frozen
    }
    pub(crate) const fn event_id(&self) -> EventIdV1 {
        self.event_id
    }
    pub(crate) const fn reason_digest(&self) -> Digest32 {
        self.reason_digest
    }
}

pub(crate) struct ProductionHeightDeadlineAuthorityV23 {
    route_id: RouteIdV1,
    frozen: FrozenBindingsV1,
    bindings: Vec<HeightBinding>,
}

impl ProductionHeightDeadlineAuthorityV23 {
    /// Observe independent selected chains concurrently. Each source retains
    /// its own pinned quorum and bounded client. No private key or Store owner
    /// enters a worker: these workers only read canonical chain identities.
    /// DOM stays on the caller thread because its scanner has one local owner.
    /// This avoids consuming three consecutive one-minute RPC budgets before
    /// the first native-height observation can be used for fresh funding.
    pub(crate) fn observe_selected_v23(
        &self,
        scanner: &crate::production_child_dom::ProductionDomF7ScannerAuthorityV1,
        dom_budget: Duration,
        sources: &[ProductionXmrDeadlineSourceV23],
    ) -> Vec<Result<Vec<ProductionDeadlineRecoveryV23>, Error>> {
        let scopes: Vec<_> = sources
            .iter()
            .map(|source| (source.leg, source.chain_id, source.adapter_profile))
            .collect();
        if self.require_complete_source_scopes_v23(&scopes).is_err() {
            return vec![Err(Error::Refused)];
        }
        // The step ceiling is a thread-local: a worker spawned below cannot see
        // it, so every observation there would fall back to its own full
        // minute, outside whatever bound the caller is holding. Resolve it on
        // this thread and re-arm the exact same instant inside each worker.
        let ceiling_v28 = route_step_deadline::armed();
        std::thread::scope(|scope| {
            let mut workers = Vec::with_capacity(sources.len());
            let mut observations = Vec::with_capacity(sources.len() + 1);
            for source in sources {
                match std::thread::Builder::new()
                    .name("xmr-height-observer".into())
                    .spawn_scoped(scope, move || {
                        let _armed = route_step_deadline::Armed::new(ceiling_v28);
                        self.observe_xmr_v23(source)
                    })
                {
                    Ok(worker) => workers.push(worker),
                    Err(_) => observations.push(Err(Error::Unavailable)),
                }
            }
            if self.has_dom_deadlines_v23() {
                observations.push(self.observe_dom_v23(scanner, dom_budget));
            }
            for worker in workers {
                // Join explicitly so a failed worker is a typed refusal, not
                // a detached job or an unwinding authority in the route loop.
                observations.push(worker.join().unwrap_or(Err(Error::Inconsistent)));
            }
            observations
        })
    }

    /// Absence of a selected observer is not evidence that its deadline is
    /// still open. Require exact coverage before any RPC or funding window can
    /// be reached, including two legs with identical chain/profile identities.
    fn require_complete_source_scopes_v23(
        &self,
        scopes: &[(LegIdV1, Digest32, Digest32)],
    ) -> Result<(), Error> {
        let expected: Vec<_> = self
            .bindings
            .iter()
            .filter(|binding| !binding.dom)
            .map(|binding| (binding.leg, binding.chain_id, binding.adapter_profile))
            .collect();
        if scopes.len() > 2
            || scopes.len() != expected.len()
            || scopes.iter().enumerate().any(|(index, scope)| {
                scopes[..index].iter().any(|prior| prior.0 == scope.0) || !expected.contains(scope)
            })
        {
            return Err(Error::Refused);
        }
        Ok(())
    }

    pub(crate) fn from_composition(
        route_id: RouteIdV1,
        composition: &ComposedBindingV2,
        frozen: FrozenBindingsV1,
    ) -> Result<Self, Error> {
        if [
            route_id,
            composition.binding_digest(),
            frozen.terms_digest,
            frozen.profile_bundle_digest,
            frozen.deployment_bundle_digest,
        ]
        .contains(&ZERO_DIGEST)
        {
            return Err(Error::Refused);
        }
        let mut bindings = Vec::with_capacity(4);
        for (position, terms) in [composition.upstream(), composition.downstream()]
            .into_iter()
            .enumerate()
        {
            for (face, leg) in [terms.dom_leg, terms.counterparty_leg]
                .into_iter()
                .enumerate()
            {
                let TimelockSpec::BlockHeight { value } = leg.deadline else {
                    continue;
                };
                if value == 0
                    || leg.chain_id.0 == ZERO_DIGEST
                    || leg.adapter_profile_hash == ZERO_DIGEST
                {
                    return Err(Error::Refused);
                }
                let tags = [
                    u8::try_from(position).map_err(|_| Error::Inconsistent)?,
                    u8::try_from(face).map_err(|_| Error::Inconsistent)?,
                ];
                let context = hash_parts(
                    b"DOM-INTEROPD/NATIVE-HEIGHT-DEADLINE/V23\0",
                    &[
                        &route_id,
                        &composition.binding_digest(),
                        &composition.route_scope_digest(),
                        &terms.settlement_id.0,
                        &terms.session_id.0,
                        &tags,
                        &leg.chain_id.0,
                        &leg.adapter_profile_hash,
                        &value.to_be_bytes(),
                        &frozen.terms_digest,
                        &frozen.profile_bundle_digest,
                        &frozen.deployment_bundle_digest,
                    ],
                )?;
                bindings.push(HeightBinding {
                    leg: if position == 0 {
                        LegIdV1::Upstream
                    } else {
                        LegIdV1::Downstream
                    },
                    chain_id: leg.chain_id.0,
                    adapter_profile: leg.adapter_profile_hash,
                    dom: face == 0,
                    height: value,
                    context,
                });
            }
        }
        Ok(Self {
            route_id,
            frozen,
            bindings,
        })
    }

    pub(crate) fn observe_dom_v23(
        &self,
        scanner: &crate::production_child_dom::ProductionDomF7ScannerAuthorityV1,
        budget: Duration,
    ) -> Result<Vec<ProductionDeadlineRecoveryV23>, Error> {
        if !self.has_dom_deadlines_v23() {
            return Ok(Vec::new());
        }
        if budget.is_zero() {
            return Err(Error::Refused);
        }
        let context = scanner
            .funding_validation_context_bounded_v23(budget)
            .map_err(dom_error)?;
        self.due(*context.chain_id(), true, None, context.current_height())
    }

    pub(crate) fn has_dom_deadlines_v23(&self) -> bool {
        self.bindings.iter().any(|binding| binding.dom)
    }

    pub(crate) fn observe_xmr_v23(
        &self,
        source: &ProductionXmrDeadlineSourceV23,
    ) -> Result<Vec<ProductionDeadlineRecoveryV23>, Error> {
        if !self.bindings.iter().any(|binding| {
            !binding.dom && binding.chain_id == source.chain_id && binding.leg == source.leg
        }) {
            return Err(Error::Refused);
        }
        let tip = source.observe()?;
        self.due_for_leg(
            source.chain_id,
            false,
            Some(source.adapter_profile),
            tip.height,
            Some(source.leg),
        )
    }

    fn due(
        &self,
        chain_id: Digest32,
        dom: bool,
        profile: Option<Digest32>,
        height: u64,
    ) -> Result<Vec<ProductionDeadlineRecoveryV23>, Error> {
        self.due_for_leg(chain_id, dom, profile, height, None)
    }

    fn due_for_leg(
        &self,
        chain_id: Digest32,
        dom: bool,
        profile: Option<Digest32>,
        height: u64,
        selected_leg: Option<LegIdV1>,
    ) -> Result<Vec<ProductionDeadlineRecoveryV23>, Error> {
        let selected: Vec<_> = self
            .bindings
            .iter()
            .filter(|binding| {
                binding.chain_id == chain_id
                    && binding.dom == dom
                    && selected_leg.is_none_or(|leg| binding.leg == leg)
            })
            .collect();
        if selected.is_empty()
            || selected
                .iter()
                .any(|binding| profile.is_some_and(|expected| expected != binding.adapter_profile))
        {
            return Err(Error::Refused);
        }
        selected
            .into_iter()
            .filter(|binding| height >= binding.height)
            .map(|binding| {
                Ok(ProductionDeadlineRecoveryV23 {
                    route_id: self.route_id,
                    frozen: self.frozen.clone(),
                    event_id: hash_parts(
                        b"DOM-INTEROPD/HEIGHT-RECOVERY-EVENT/V23\0",
                        &[&binding.context],
                    )?,
                    // Stable across observed-tip advances and takeover. The current
                    // observer is the capability producer, not an event field that
                    // could change under the same durable idempotency key.
                    reason_digest: hash_parts(
                        b"DOM-INTEROPD/HEIGHT-RECOVERY-REASON/V23\0",
                        &[&binding.context],
                    )?,
                })
            })
            .collect()
    }
}

/// Exact selected network/profile, endpoint set and negotiated quorum.
/// No signer, callback, generic evidence constructor, or operator key enters.
pub(crate) struct ProductionXmrDeadlineSourceV23 {
    leg: LegIdV1,
    chain_id: Digest32,
    genesis: Digest32,
    adapter_profile: Digest32,
    daemon_urls: Vec<String>,
    network: XmrNetwork,
    quorum: usize,
    executor: tokio::runtime::Runtime,
}

impl ProductionXmrDeadlineSourceV23 {
    pub(crate) fn new(
        leg: LegIdV1,
        deployment: ResolvedMoneroDeploymentV1,
        profile: XmrAdapterProfileV1,
        daemon_urls: Vec<String>,
    ) -> Result<Self, Error> {
        let ChainKindV1::Monero { network } = &deployment.profile().kind else {
            return Err(Error::Refused);
        };
        let (expected, observed) = match network {
            MoneroNetworkV1::Mainnet => {
                (xmr_setup_profile::XmrNetwork::Mainnet, XmrNetwork::Mainnet)
            }
            MoneroNetworkV1::Stagenet => (
                xmr_setup_profile::XmrNetwork::Stagenet,
                XmrNetwork::Stagenet,
            ),
            MoneroNetworkV1::Testnet => {
                (xmr_setup_profile::XmrNetwork::Testnet, XmrNetwork::Testnet)
            }
        };
        if profile.network != expected || deployment.deployment().genesis_hash == ZERO_DIGEST {
            return Err(Error::Refused);
        }
        validate_source_urls(&profile, &daemon_urls)?;
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            leg,
            chain_id: deployment.profile().chain_id.0,
            genesis: deployment.deployment().genesis_hash,
            adapter_profile: deployment.profile_digest(),
            daemon_urls,
            network: observed,
            quorum: usize::from(profile.rpc_quorum),
            executor,
        })
    }

    fn observe(&self) -> Result<CanonicalTip, Error> {
        // The production runtime is synchronous, like the existing XMR funding
        // observer. Refuse nested async use rather than panic while creating an
        // alternate runtime or silently dropping the deadline check.
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Error::Unavailable);
        }
        self.executor.block_on(async {
            // Sixty seconds is this observation's own budget; when a ceiling
            // is armed around the observation pass, narrow to what it leaves.
            // With nothing armed the figure is unchanged.
            let budget = match route_step_deadline::remaining(Duration::from_secs(60)) {
                Some(budget) => budget,
                None => return Err(Error::Unavailable),
            };
            tokio::time::timeout(budget, async {
                // This current-thread executor is idle between observations.
                // An HTTP keep-alive socket may have closed while its driver
                // was not being polled. Retain connections only within this
                // observation, so a stale pooled POST cannot close funding
                // for the next entire route round. All quorum, genesis and
                // stable-tip checks still run under the same deadline.
                let nodes = self
                    .daemon_urls
                    .iter()
                    .map(|url| HttpXmrRpc::new(url.clone()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(observer_error)?;
                let pool =
                    XmrRpcPool::new(nodes, self.network, self.quorum).map_err(observer_error)?;
                if pool.block_hash(0).await.map_err(observer_error)? != self.genesis {
                    return Err(Error::Refused);
                }
                let tip = pool.canonical_tip().await.map_err(observer_error)?;
                if pool.block_hash(tip.height).await.map_err(observer_error)? != tip.hash {
                    return Err(Error::Inconsistent);
                }
                if pool.block_hash(0).await.map_err(observer_error)? != self.genesis {
                    return Err(Error::Refused);
                }
                if pool.canonical_tip().await.map_err(observer_error)? != tip {
                    return Err(Error::Unavailable);
                }
                Ok(tip)
            })
            .await
            .unwrap_or(Err(Error::Unavailable))
        })
    }
}

fn validate_source_urls(
    profile: &XmrAdapterProfileV1,
    daemon_urls: &[String],
) -> Result<(), Error> {
    use crate::production_chain_services::{
        validate_endpoint_text, ProductionChainServicesErrorV1,
    };
    if daemon_urls.len() != usize::from(profile.rpc_node_count)
        || !crate::production_xmr_quorum::valid_quorum_v5(
            daemon_urls.len(),
            usize::from(profile.rpc_quorum),
        )
    {
        return Err(Error::Refused);
    }
    let mut seen = BTreeSet::new();
    for url in daemon_urls {
        validate_endpoint_text(url, ProductionChainServicesErrorV1::InvalidEncoding)
            .map_err(|_| Error::Refused)?;
        if !seen.insert(url.trim_end_matches('/').to_ascii_lowercase()) {
            return Err(Error::Refused);
        }
    }
    Ok(())
}

fn observer_error(error: XmrObserverError) -> Error {
    match error {
        XmrObserverError::RpcTransport
        | XmrObserverError::NotSynchronized
        | XmrObserverError::StaleTip
        | XmrObserverError::ConflictingCanonicalTip
        | XmrObserverError::ConflictingBlockHash
        | XmrObserverError::ConflictingTransactionStatus => Error::Unavailable,
        XmrObserverError::WrongNetwork => Error::Refused,
        XmrObserverError::MalformedResponse
        | XmrObserverError::InvalidQuorum { .. }
        | XmrObserverError::InvalidCursor => Error::Inconsistent,
    }
}

fn dom_error(error: adapter_dom_real::RealDomError) -> Error {
    use adapter_dom_real::RealDomError as R;
    use dom_scriptless_chain_adapter::ChainAdapterError as C;
    match error {
        R::Chain(C::TemporarilyUnavailable | C::CapabilityUnavailable | C::ReorgDetected)
        | R::EvidenceNotFound
        | R::InsufficientConfirmations => Error::Unavailable,
        R::Chain(C::AuthenticationFailed | C::IdentityMismatch | C::InvalidConfiguration) => {
            Error::Refused
        }
        _ => Error::Inconsistent,
    }
}

#[cfg(test)]
#[path = "production_height_timer_v23_tests.rs"]
mod tests;
