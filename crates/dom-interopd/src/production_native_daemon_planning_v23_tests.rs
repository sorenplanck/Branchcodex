//! First-export planning from real registry, time-ladder and DLEQ admission.
//! This is NOT AuthenticatedProductionInputs and grants no daemon operation.
//! The final loader must authenticate the exported files again before launch.
use super::*;
use crate::production_config::ProductionPathReferencesV1;
use crate::production_inputs::planning_context_v23::{
    ProductionPreF6PlanningContextV23, ProductionPreF6PlanningInputsV23,
};
use deployment_registry::SignedRegistryV1;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

#[path = "production_native_daemon_common_v23_tests.rs"]
mod common_v23;
#[path = "production_native_daemon_first_export_v23_tests.rs"]
mod first_export_v23;
pub(crate) use common_v23::NativeDaemonOwnerPinsV23;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct NativeDaemonPlanningInputsV23 {
    pub signed_registry: SignedRegistryV1,
    pub authorities: ProductionAuthorityBundleV1,
    pub terms: [SettlementTermsV1; 2],
    pub signed_policy: SignedRouteTimePolicyV2,
    pub signed_evidence: SignedRouteTimeEvidenceV2,
    pub rosters: ProductionRelayRosterBundleV1,
    pub participants: ProductionParticipantBindingBundleV1,
    /// Bytes of the ACTUAL completed ceremony, with its exact two stage pins.
    pub contracts_bootstrap: Vec<u8>,
    pub route_id: RouteIdV1,
    pub network_id: Digest32,
    pub minimum_registry_epoch: u64,
    pub now_seconds: u64,
}

/// Completes the participant bundle from the planning admission and registry.
pub(crate) type ParticipantFinisherV25<'a> = Box<
    dyn FnOnce(
            &AuthenticatedRouteAdmissionV1,
            &ResolvedRegistryV1,
        ) -> Result<ProductionParticipantBindingBundleV1>
        + 'a,
>;

/// Private fields can only be populated after native verification below.
/// No secret, transport grant, F6 approval, or substitute production token.
pub(crate) struct NativeDaemonPlanningContextV23 {
    admission: AuthenticatedRouteAdmissionV1,
    composition: ComposedBindingV2,
    registry: ResolvedRegistryV1,
    authorities: ProductionAuthorityBundleV1,
    rosters: ProductionRelayRosterBundleV1,
    sessions: NativeDaemonSessionsV25,
    contracts: AuthenticatedContractsBootstrapV1,
    secp: SecpContext,
    policy_authority_digest: Digest32,
    evidence_authority_digest: Digest32,
    signed_policy: SignedRouteTimePolicyV2,
    signed_evidence: SignedRouteTimeEvidenceV2,
    participants: ProductionParticipantBindingBundleV1,
    paths: ProductionPathReferencesV1,
    root: PathBuf,
}

/// The single admitted counterparty family of both positions. Exactly one
/// variant is populated by native verification; no mixed pair is represented.
enum NativeDaemonSessionsV25 {
    Monero([AuthenticatedXmrSessionBindingsV1; 2]),
    Solana([AuthenticatedSolanaSessionBindingsV1; 2]),
}

impl NativeDaemonPlanningContextV23 {
    pub(crate) fn prepare(
        root: &Path,
        paths: ProductionPathReferencesV1,
        input: NativeDaemonPlanningInputsV23,
    ) -> Result<Self> {
        Self::prepare_for_families_v25(
            root,
            paths,
            input,
            [crate::production_config::ProductionChainFamilyV11::Xmr; 2],
        )
    }

    /// Same planning checkpoint for an explicitly selected same-family pair.
    /// XMR keeps its original refusal text; SOL requires two DLEQ admissions.
    pub(crate) fn prepare_for_families_v25(
        root: &Path,
        paths: ProductionPathReferencesV1,
        input: NativeDaemonPlanningInputsV23,
        families: [crate::production_config::ProductionChainFamilyV11; 2],
    ) -> Result<Self> {
        Self::prepare_inner_v25(root, paths, input, families, None)
    }

    /// Planning for participant proofs that sign the admission's frozen terms
    /// digest, which exists only once the time ladder and the admission have
    /// run. `finish` receives that admission and the resolved registry, and
    /// returns the complete bundle; the bundle is then authenticated exactly
    /// as the daemon loader will authenticate it. `input.participants` is the
    /// bundle without those proofs and is replaced.
    pub(crate) fn prepare_for_families_with_participants_v25(
        root: &Path,
        paths: ProductionPathReferencesV1,
        input: NativeDaemonPlanningInputsV23,
        families: [crate::production_config::ProductionChainFamilyV11; 2],
        finish: ParticipantFinisherV25<'_>,
    ) -> Result<Self> {
        Self::prepare_inner_v25(root, paths, input, families, Some(finish))
    }

    fn prepare_inner_v25(
        root: &Path,
        paths: ProductionPathReferencesV1,
        input: NativeDaemonPlanningInputsV23,
        families: [crate::production_config::ProductionChainFamilyV11; 2],
        finish: Option<ParticipantFinisherV25<'_>>,
    ) -> Result<Self> {
        use crate::production_config::ProductionChainFamilyV11;
        if families != [ProductionChainFamilyV11::Xmr; 2]
            && families != [ProductionChainFamilyV11::Sol; 2]
        {
            return Err("native planning requires one selected XMR or SOL family pair".into());
        }
        require_private_parent(root)?;
        if input.now_seconds == 0 || input.route_id == [0; 32] {
            return Err("native planning scope".into());
        }
        let secp = SecpContext::new(&VERIFICATION_CONTEXT_SEED_V1);
        let registry_path = root.join(paths.get(ProductionPathRoleV1::RegistryStore));
        require_private_parent(registry_path.parent().ok_or("registry parent")?)?;
        let store = RegistryStoreV1::create(&registry_path)?;
        let [upstream, downstream] = &input.terms;
        let planning_input = ProductionPreF6PlanningInputsV23 {
            signed_registry: &input.signed_registry,
            authorities: &input.authorities,
            terms: [upstream, downstream],
            signed_policy: &input.signed_policy,
            signed_evidence: &input.signed_evidence,
            rosters: &input.rosters,
            route_id: input.route_id,
            network_id: input.network_id,
            minimum_registry_epoch: input.minimum_registry_epoch,
            now_seconds: input.now_seconds,
        };
        let time_config = planning_input.time_store_config(&secp)?;
        let policy_authority_digest = time_config.policy_authority_set_digest();
        let evidence_authority_digest = time_config.evidence_authority_set_digest();
        // A distinct planning journal is not the daemon's mutable time store.
        let time_path = root.join("planning-native-time-v23.sqlite3");
        let mut time = DurableRouteTimeAnchorStoreV2::create(&time_path, time_config)?;
        let planning =
            ProductionPreF6PlanningContextV23::prepare(store, &mut time, &planning_input, &secp)?;
        let (admission, composition, registry) = planning.into_parts();
        // Proofs that sign the frozen terms digest can only be produced now,
        // after admission; without a finisher the supplied bundle stands.
        let participants = match finish {
            None => input.participants.clone(),
            Some(finish) => finish(&admission, &registry)?,
        };
        let authenticated = authenticate_participant_bundle(
            &participants,
            ParticipantAuthenticationContextV1 {
                secp: &secp,
                rosters: &input.rosters,
                registry: &registry,
                upstream,
                downstream,
                admission: &admission,
                now: input.now_seconds,
            },
        )?;
        let sessions = if families == [ProductionChainFamilyV11::Xmr; 2] {
            if authenticated.monero.iter().any(Option::is_none)
                || authenticated.evm.iter().any(Option::is_some)
                || authenticated.bitcoin.iter().any(Option::is_some)
                || authenticated.solana.iter().any(Option::is_some)
            {
                return Err("native planning requires two actual XMR admissions".into());
            }
            let [Some(up), Some(down)] = authenticated.monero else {
                return Err("native planning missing native sessions".into());
            };
            NativeDaemonSessionsV25::Monero([up, down])
        } else {
            if authenticated.solana.iter().any(Option::is_none)
                || authenticated.evm.iter().any(Option::is_some)
                || authenticated.bitcoin.iter().any(Option::is_some)
                || authenticated.monero.iter().any(Option::is_some)
            {
                return Err("native planning requires two actual SOL admissions".into());
            }
            let [Some(up), Some(down)] = authenticated.solana else {
                return Err("native planning missing native SOL sessions".into());
            };
            NativeDaemonSessionsV25::Solana([up, down])
        };
        let contracts = authenticate_contracts_bootstrap_v1(
            &input.contracts_bootstrap,
            &composition,
            &registry,
            &input.rosters,
            &secp,
        )?;
        // Public artifacts are published only after all cross-bindings verify.
        for (role, bytes) in [
            (
                ProductionPathRoleV1::RegistryAuthorities,
                input.authorities.canonical_bytes()?,
            ),
            (
                ProductionPathRoleV1::UpstreamTerms,
                upstream.canonical_bytes()?,
            ),
            (
                ProductionPathRoleV1::DownstreamTerms,
                downstream.canonical_bytes()?,
            ),
            (
                ProductionPathRoleV1::ParticipantBindings,
                participants.canonical_bytes()?,
            ),
            (
                ProductionPathRoleV1::RelayRoster,
                input.rosters.canonical_bytes()?,
            ),
            (
                ProductionPathRoleV1::TimePolicy,
                input.signed_policy.canonical_bytes()?,
            ),
            (
                ProductionPathRoleV1::TimeEvidence,
                input.signed_evidence.canonical_bytes()?,
            ),
        ] {
            publish(root, paths.get(role), &bytes)?;
        }
        drop(time);
        Ok(Self {
            admission,
            composition,
            registry,
            authorities: input.authorities,
            rosters: input.rosters,
            sessions,
            contracts,
            secp,
            policy_authority_digest,
            evidence_authority_digest,
            signed_policy: input.signed_policy,
            signed_evidence: input.signed_evidence,
            participants,
            paths,
            root: root.to_path_buf(),
        })
    }

    pub(crate) fn admission(&self) -> &AuthenticatedRouteAdmissionV1 {
        &self.admission
    }
    pub(crate) fn composition(&self) -> &ComposedBindingV2 {
        &self.composition
    }
    pub(crate) fn resolved_registry(&self) -> &ResolvedRegistryV1 {
        &self.registry
    }
    pub(crate) fn registry_authorities(&self) -> &AuthoritySetV1 {
        &self.authorities.registry
    }
    pub(crate) fn time_policy_authorities(&self) -> &AuthoritySetV1 {
        &self.authorities.time_policy
    }
    pub(crate) fn time_evidence_authorities(&self) -> &AuthoritySetV1 {
        &self.authorities.time_evidence
    }
    pub(crate) fn roster_bundle(&self) -> &ProductionRelayRosterBundleV1 {
        &self.rosters
    }
    /// Callers select this only for an XMR-planned context; a SOL context has
    /// no Monero session and refuses loudly instead of inventing one.
    pub(crate) fn monero_session(&self, leg: LegIdV1) -> &AuthenticatedXmrSessionBindingsV1 {
        let NativeDaemonSessionsV25::Monero(sessions) = &self.sessions else {
            panic!("native planning context was admitted for SOL, not XMR");
        };
        &sessions[match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        }]
    }
    /// DLEQ-authenticated Solana escrow session of a SOL-planned context.
    pub(crate) fn solana_session(&self, leg: LegIdV1) -> Result<&AuthenticatedSolanaSessionBindingsV1> {
        let NativeDaemonSessionsV25::Solana(sessions) = &self.sessions else {
            return Err("native planning context has no SOL sessions".into());
        };
        Ok(&sessions[match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        }])
    }
    /// Family of both positions, fixed by native verification in `prepare`.
    pub(crate) fn families_v25(&self) -> [crate::production_config::ProductionChainFamilyV11; 2] {
        match self.sessions {
            NativeDaemonSessionsV25::Monero(_) => {
                [crate::production_config::ProductionChainFamilyV11::Xmr; 2]
            }
            NativeDaemonSessionsV25::Solana(_) => {
                [crate::production_config::ProductionChainFamilyV11::Sol; 2]
            }
        }
    }
    pub(crate) fn contracts_bootstrap(&self) -> &AuthenticatedContractsBootstrapV1 {
        &self.contracts
    }
    pub(crate) fn verification_context(&self) -> &SecpContext {
        &self.secp
    }
}

fn require_private_parent(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || std::fs::canonicalize(path)? != path
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("native planning parent".into());
    }
    Ok(())
}

fn publish(root: &Path, relative: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
    let relative = relative.as_ref();
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("native planning artifact path".into());
    }
    let target = root.join(relative);
    require_private_parent(target.parent().ok_or("native planning artifact parent")?)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&target)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::File::open(target.parent().ok_or("native planning artifact parent")?)?.sync_all()?;
    Ok(())
}
