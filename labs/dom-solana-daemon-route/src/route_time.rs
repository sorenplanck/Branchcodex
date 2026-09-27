//! The route's time authority: a signed static policy and the signed evidence that
//! revalidates it.
//!
//! These are the last two artifacts before the route has a time anchor, and between
//! them they settle four pins: the two authority-set digests, the policy digest and
//! the evidence digest.
//!
//! # The policy is reconstructed, not chosen
//!
//! The daemon does not accept the policy on the artifact's word. It decodes the file,
//! rebuilds the policy from the authenticated registry and the two frozen terms with
//! `RouteTimePolicyV2::from_registry`, and refuses unless the two are equal. So the
//! only thing a provisioner chooses is the `limits`; the network id, registry digest
//! and epoch, both terms hashes, the route scope and all three checkpoint bindings are
//! derived. This module therefore builds the policy with that same constructor against
//! the registry it loads back through the authority bundle -- the authenticated path,
//! not the manifest it happened to write.
//!
//! # What the limits must satisfy
//!
//! `validate_static` refuses a zero in any budget, a window that does not open before
//! it closes, and an evidence age or funding delay longer than the window itself. The
//! manifest adds an outer bound: the policy's window must sit inside the manifest's
//! own `valid_from`/`expires_at`, which is why the registry reports those and this
//! module reads them from there.
//!
//! # The evidence is an observation, and it is bounded
//!
//! `CanonicalTimeCheckpointV2::new` copies every identity field from the policy's
//! binding and takes only public chain facts from the caller: a frozen anchor
//! (height, hash, parent hash), a conservative wall-clock interval for that anchor,
//! and a canonical tip with a commitment to the finality proof behind it.
//! `validate_checkpoint` then refuses a zero hash, an inverted interval, an interval
//! wider than the policy allows, an anchor whose lower endpoint is further in the
//! future than the policy's skew, an observation later than the anchor's upper
//! endpoint plus the allowed skew, and a tip that does not clear
//! `anchor_height + min_confirmations - 1`.
//!
//! On a live route those facts come from the DOM node and the two clusters. Here they
//! are inputs, and the module says so rather than inventing an observation that would
//! look like one.

use std::path::Path;

use btc_crypto::SecpContext;
use deployment_registry::{RegistryStoreV1, RegistryValidationPolicyV1};
use dom_interopd::ProductionAuthorityBundleV1;
use kaystra_core::terms::SettlementTermsV1;
use route_time_anchor::{
    CanonicalAnchorObservationV2, CanonicalCheckpointObservationV2, CanonicalTimeCheckpointV2,
    CanonicalTimeRangeV2, CanonicalTipObservationV2, DurableRouteTimeAnchorStoreV2,
    RouteTimeAnchorStoreConfigV2, RouteTimeEvidenceV2, RouteTimeEvidenceVerificationContextV2,
    RouteTimePolicyLimitsV2, RouteTimePolicyV2, RouteTimePolicyVerificationContextV2,
    SignedRouteTimeEvidenceV2, SignedRouteTimePolicyV2, TimeAnchorSignatureV2,
};

use crate::registry::{
    authority_aux, authority_secret, ProvisionedSolanaRegistryV1, AUTHORITY_ROLES,
    AUTHORITY_THRESHOLD, TIME_EVIDENCE_ROLE, TIME_POLICY_ROLE,
};

/// One chain's public observation behind one checkpoint.
///
/// Every field is a public fact about a canonical chain. Nothing here is secret and
/// nothing here is derived: a caller that cannot observe a chain cannot fill this in,
/// which is the intended shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainObservationV1 {
    /// The frozen canonical anchor.
    pub anchor_height: u64,
    pub anchor_hash: [u8; 32],
    /// The anchor's parent, so the claim is not a bare height and hash.
    pub parent_hash: [u8; 32],
    /// Conservative wall-clock endpoints for the anchor's native time. Conservative
    /// means wide enough to be true, and no wider than the policy admits.
    pub time_lower_seconds: u64,
    pub time_upper_seconds: u64,
    /// The canonical tip proving the anchor has its required confirmations.
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
    /// Commitment to the chain-specific finality proof behind that tip.
    pub canonicality_evidence_digest: [u8; 32],
}

impl ChainObservationV1 {
    fn into_observation(self) -> CanonicalCheckpointObservationV2 {
        CanonicalCheckpointObservationV2::new(
            CanonicalAnchorObservationV2::new(self.anchor_height, self.anchor_hash, self.parent_hash),
            CanonicalTimeRangeV2::new(self.time_lower_seconds, self.time_upper_seconds),
            CanonicalTipObservationV2::new(
                self.tip_height,
                self.tip_hash,
                self.canonicality_evidence_digest,
            ),
        )
    }
}

/// Everything the time provisioner is given.
#[derive(Clone, Copy, Debug)]
pub struct RouteTimeInputV1<'a> {
    pub state_dir: &'a Path,
    /// The layout's own relative path for `ProductionPathRoleV1::RegistryStore`, so the
    /// policy is derived from the registry the daemon will authenticate.
    pub registry_relative: &'a str,
    /// The layout's own relative path for `ProductionPathRoleV1::RegistryAuthorities`.
    pub authorities_relative: &'a str,
    /// The layout's own relative path for `ProductionPathRoleV1::TimePolicy`.
    pub policy_relative: &'a str,
    /// The layout's own relative path for `ProductionPathRoleV1::TimeEvidence`.
    pub evidence_relative: &'a str,
    pub registry: &'a ProvisionedSolanaRegistryV1,
    pub upstream: &'a SettlementTermsV1,
    pub downstream: &'a SettlementTermsV1,
    /// Trusted wall clock, seconds. The same second the registry was validated at.
    pub now_seconds: u64,
    /// Where the throwaway time-anchor store used to verify these artifacts goes.
    ///
    /// Not inside `state_dir`: the daemon's own time-anchor store is a managed path it
    /// requires to be absent on create, so a store left there would make the layout
    /// refuse the directory.
    pub provisioning_dir: &'a Path,
    /// The three observations, in the policy's own checkpoint order: hub, upstream
    /// counterparty, downstream counterparty.
    pub hub: ChainObservationV1,
    pub upstream_chain: ChainObservationV1,
    pub downstream_chain: ChainObservationV1,
    /// Monotonic revalidation sequence. Zero is refused.
    pub sequence: u64,
}

/// The four pins the time artifacts determine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvisionedRouteTimeV1 {
    pub time_policy_authority_set_digest: [u8; 32],
    pub time_evidence_authority_set_digest: [u8; 32],
    pub time_policy_digest: [u8; 32],
    pub time_evidence_digest: [u8; 32],
}

/// Limits derived from the manifest's window.
///
/// Conservative and stated rather than tuned. Every budget is non-zero because a zero
/// one is refused, and none exceeds the window, because `validate_static` refuses an
/// evidence age or funding delay longer than the policy's own lifetime.
fn limits(registry: &ProvisionedSolanaRegistryV1) -> RouteTimePolicyLimitsV2 {
    RouteTimePolicyLimitsV2 {
        // Exactly the manifest's window: the policy may not be valid outside the
        // deployment that authorises it, and a narrower window would expire first for
        // no stated reason.
        valid_from_seconds: registry.valid_from_seconds,
        expires_at_seconds: registry.expires_at_seconds,
        max_evidence_age_seconds: 3_600,
        max_anchor_interval_width_seconds: 600,
        max_anchor_time_skew_seconds: 900,
        max_future_skew_seconds: 120,
        max_upstream_funding_anchor_delay_seconds: 1_800,
        max_downstream_funding_anchor_delay_seconds: 1_800,
        hub_margin_seconds: 600,
        counterparty_margin_seconds: 600,
    }
}

/// Load the registry back the way the daemon does: through the authenticated bundle.
fn resolve_registry(
    input: &RouteTimeInputV1<'_>,
    secp: &SecpContext,
) -> Result<deployment_registry::ResolvedRegistryV1, String> {
    let bundle = decode_authority_bundle(input)?;
    let store = RegistryStoreV1::open_existing(&input.state_dir.join(input.registry_relative))
        .map_err(|error| format!("registry store: {error:?}"))?;
    store
        .load_current(
            bundle.registry(),
            secp,
            RegistryValidationPolicyV1 {
                now_seconds: input.now_seconds,
                expected_network_id: input.registry.network_id,
                minimum_epoch: input.registry.epoch,
            },
        )
        .map_err(|error| format!("registry load: {error:?}"))?
        .ok_or_else(|| "the registry store holds no current registry".to_owned())
}

/// Sign one digest with two of the three members of one authority role.
///
/// Two, not three: the threshold is what the set declares, and signing with every
/// member would never exercise it.
fn sign(
    secp: &SecpContext,
    role_index: usize,
    digest: &[u8; 32],
) -> Result<Vec<TimeAnchorSignatureV2>, String> {
    let (role, label) = AUTHORITY_ROLES[role_index];
    let mut signatures = Vec::with_capacity(usize::from(AUTHORITY_THRESHOLD));
    for index in 0..u8::try_from(AUTHORITY_THRESHOLD).unwrap_or(u8::MAX) {
        let (signature, _xonly) = secp
            .sign_bip340(
                &authority_secret(role, index, label),
                digest,
                &authority_aux(role, index),
            )
            .map_err(|error| format!("{label} signature: {error:?}"))?;
        signatures.push(TimeAnchorSignatureV2 {
            signer_index: u16::from(index),
            signature,
        });
    }
    Ok(signatures)
}

/// Build, sign and write both time artifacts; return the four pins.
pub fn provision(input: &RouteTimeInputV1<'_>) -> Result<ProvisionedRouteTimeV1, String> {
    let secp = SecpContext::new(&[0x5a; 32]);
    let resolved = resolve_registry(input, &secp)?;

    let policy = RouteTimePolicyV2::from_registry(
        &resolved,
        input.upstream,
        input.downstream,
        limits(input.registry),
    )
    .map_err(|error| format!("route time policy: {error:?}"))?;
    let policy_digest = policy
        .policy_digest()
        .map_err(|error| format!("policy digest: {error:?}"))?;
    let signed_policy = SignedRouteTimePolicyV2::new(&policy, sign(&secp, TIME_POLICY_ROLE, &policy_digest)?)
        .map_err(|error| format!("signed policy: {error:?}"))?;
    crate::owner_only::write(
        &input.state_dir.join(input.policy_relative),
        &signed_policy
            .canonical_bytes()
            .map_err(|error| format!("signed policy bytes: {error:?}"))?,
    )?;

    // The checkpoint identity comes from the policy binding; the caller supplies only
    // what a chain observer can see. The order is the policy's own: hub, upstream
    // counterparty, downstream counterparty.
    let bindings = policy.checkpoint_bindings();
    let checkpoints = [
        CanonicalTimeCheckpointV2::new(bindings[0], input.hub.into_observation()),
        CanonicalTimeCheckpointV2::new(bindings[1], input.upstream_chain.into_observation()),
        CanonicalTimeCheckpointV2::new(bindings[2], input.downstream_chain.into_observation()),
    ];
    let evidence = RouteTimeEvidenceV2::new(
        &policy,
        input.sequence,
        input.now_seconds,
        // Inside the policy's window and no longer than the evidence age it admits,
        // both of which `validate_at` refuses otherwise.
        input
            .now_seconds
            .checked_add(limits(input.registry).max_evidence_age_seconds)
            .ok_or_else(|| "the evidence lifetime overflows".to_owned())?
            .min(input.registry.expires_at_seconds),
        checkpoints,
    )
    .map_err(|error| format!("route time evidence: {error:?}"))?;
    let evidence_digest = evidence
        .evidence_digest()
        .map_err(|error| format!("evidence digest: {error:?}"))?;
    let signed_evidence =
        SignedRouteTimeEvidenceV2::new(&evidence, sign(&secp, TIME_EVIDENCE_ROLE, &evidence_digest)?)
            .map_err(|error| format!("signed evidence: {error:?}"))?;
    crate::owner_only::write(
        &input.state_dir.join(input.evidence_relative),
        &signed_evidence
            .canonical_bytes()
            .map_err(|error| format!("signed evidence bytes: {error:?}"))?,
    )?;

    // The two authority-set pins come from the daemon's OWN computation, not from
    // `AuthoritySetV1::authority_set_digest`.
    //
    // Those are two different values for the same key set: `deployment-registry` hashes
    // an authority set under "DOM-INTEROP/DEPLOYMENT..." and `route-time-anchor` hashes
    // it under its own `ROUTE_TIME_AUTHORITY_SET_DOMAIN_V2`. The registry pin wants the
    // first; `time_policy_authority_set_digest` and `time_evidence_authority_set_digest`
    // want the second, because the loader compares them with
    // `RouteTimeAnchorStoreConfigV2`'s accessors. Measuring them with the registry's
    // formula produced a `PinMismatch` the artifacts could not explain, since every
    // artifact did hash to the pin that named it.
    //
    // `route_time_anchor::authority_set_digest` is `pub(crate)`, so rather than restate
    // its formula -- which would drift the first time it changed -- this builds the same
    // store config the loader builds and reads the two values off it.
    let bundle = decode_authority_bundle(input)?;
    let time_config = RouteTimeAnchorStoreConfigV2::new(
        &resolved,
        input.upstream,
        input.downstream,
        bundle.time_policy(),
        bundle.time_evidence(),
        &secp,
    )
    .map_err(|error| format!("route time store config: {error:?}"))?;
    // The same config carries three values the loader also compares with pins the
    // registry and the terms determine. Checking them here turns a later `PinMismatch`
    // into a named disagreement at the point where both sides are in hand.
    if time_config.network_id() != input.registry.network_id {
        return Err("the time config names another interop network".to_owned());
    }
    if time_config.registry_digest() != input.registry.manifest_digest {
        return Err("the time config names another registry manifest".to_owned());
    }
    if time_config.route_scope_digest() != policy.route_scope_digest() {
        return Err("the time config names another route scope".to_owned());
    }

    // Prove the ladder these two artifacts imply, through the daemon's own store.
    //
    // The loader installs the policy and the evidence and then proves the ladder, and
    // every distinct failure on that path -- an invalid policy, invalid evidence, a
    // registry mismatch, an anchor outside its window, an interval that cannot hold --
    // reaches the caller as one word: `TimeRefused`. Proving it here, where the concrete
    // `RouteTimeAnchorErrorV2` is still in hand, means a provisioner that writes an
    // unusable schedule learns which rule it broke instead of learning that the daemon
    // declined.
    prove_the_ladder(
        input,
        &resolved,
        &secp,
        &bundle,
        &signed_policy,
        &signed_evidence,
        time_config,
    )?;

    Ok(ProvisionedRouteTimeV1 {
        time_policy_authority_set_digest: time_config.policy_authority_set_digest(),
        time_evidence_authority_set_digest: time_config.evidence_authority_set_digest(),
        time_policy_digest: policy_digest,
        time_evidence_digest: evidence_digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn prove_the_ladder(
    input: &RouteTimeInputV1<'_>,
    resolved: &deployment_registry::ResolvedRegistryV1,
    secp: &SecpContext,
    bundle: &ProductionAuthorityBundleV1,
    signed_policy: &SignedRouteTimePolicyV2,
    signed_evidence: &SignedRouteTimeEvidenceV2,
    config: RouteTimeAnchorStoreConfigV2,
) -> Result<(), String> {
    crate::owner_only::directory(input.provisioning_dir)?;
    let path = input.provisioning_dir.join("route-time-anchor-check.v1.sqlite3");
    // A fresh store each time: this proves the artifacts, not the history of a store.
    if path.exists() {
        std::fs::remove_file(&path).map_err(|error| format!("stale check store: {error}"))?;
    }
    let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config)
        .map_err(|error| format!("time anchor check store: {error:?}"))?;
    let policy_context = RouteTimePolicyVerificationContextV2::new(
        bundle.time_policy(),
        secp,
        resolved,
        input.upstream,
        input.downstream,
    );
    store
        .install_policy(signed_policy, policy_context, input.now_seconds)
        .map_err(|error| format!("the signed policy does not install: {error:?}"))?;
    // Both contexts are `Copy`, so one of each is enough.
    let evidence_context =
        RouteTimeEvidenceVerificationContextV2::new(policy_context, bundle.time_evidence());
    store
        .install_evidence(signed_evidence, evidence_context, input.now_seconds)
        .map_err(|error| format!("the signed evidence does not install: {error:?}"))?;
    store
        .prove_route_ladder(evidence_context, input.now_seconds)
        .map_err(|error| format!("the route ladder does not verify: {error:?}"))?;
    Ok(())
}

fn decode_authority_bundle(
    input: &RouteTimeInputV1<'_>,
) -> Result<ProductionAuthorityBundleV1, String> {
    let bytes = std::fs::read(input.state_dir.join(input.authorities_relative))
        .map_err(|error| format!("authority bundle: {error}"))?;
    ProductionAuthorityBundleV1::decode_canonical(&bytes)
        .map_err(|error| format!("authority bundle decode: {error:?}"))
}
