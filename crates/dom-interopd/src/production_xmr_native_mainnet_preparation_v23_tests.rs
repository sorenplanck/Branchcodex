//! Connected mainnet preparation stages. The actual daemon still owns C/D,
//! funding authorization, wallet reservations and all executable Contracts state.
use super::*;
use xmr_graph_wallet_tests::native_observation_v23::{NativeDomSnapshotV23, RouteFundingOwnerV23};

impl NativeXmrColdStartV23 {
    pub(crate) fn start_mainnet_baseline_v23(
        &self,
        tip: u64,
        credentials: &NativeXmrDaemonCredentialsV23,
    ) -> ColdStartResult<NativeDomSnapshotV23> {
        let signed = self.signed_registry()?;
        let manifest = deployment_registry::RegistryManifestV1::decode(signed.manifest_bytes())?;
        let authorities = self.authority_bundle()?;
        let registry = signed.verify(
            authorities.registry(),
            &SecpContext::new(&[29; 32]),
            deployment_registry::RegistryValidationPolicyV1 {
                now_seconds: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                expected_network_id: manifest.network_id,
                minimum_epoch: manifest.epoch,
            },
        )?;
        NativeDomSnapshotV23::start_baseline_for_daemons_v23(
            registry.resolve_dom()?,
            tip,
            [
                zeroize::Zeroizing::new(std::str::from_utf8(&credentials.bearer[0])?.to_owned()),
                zeroize::Zeroizing::new(std::str::from_utf8(&credentials.bearer[1])?.to_owned()),
            ],
        )
    }

    pub(crate) fn mainnet_node_config_v23(
        &self,
        baseline: &NativeDomSnapshotV23,
    ) -> ColdStartResult<crate::production_node::ProductionNodeConfigV1> {
        use crate::production_node::*;
        let identity = baseline.adapter().expected_identity();
        identity.validate()?;
        if identity.network != "mainnet"
            || self
                .terms
                .iter()
                .any(|terms| terms.dom_leg.chain_id.0 != identity.chain_id)
        {
            return Err("baseline does not belong to the cold mainnet route".into());
        }
        Ok(ProductionNodeConfigV1::from_parts(
            DomNodeEndpointV1::new(baseline.endpoint())?,
            ProductionNodeIdentityV1 {
                network: identity.network.clone(),
                network_magic: identity.network_magic,
                chain_id: identity.chain_id,
                genesis_hash: identity.genesis_hash,
                protocol_version: identity.protocol_version,
                range_proof_serialization_version: identity.range_proof_serialization_version,
            },
            ProductionNodeBoundsV1 {
                connect_timeout_ms: 2_000,
                request_timeout_ms: 5_000,
                history_limit: 4096,
            },
        )?)
    }

    /// One signed time observation is shared by both actor exports.
    pub(crate) fn observe_mainnet_time_v23(
        &self,
        node: &crate::production_node::ProductionNodeConfigV1,
        bearer: zeroize::Zeroizing<String>,
        funding: &RouteFundingOwnerV23,
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
    ) -> ColdStartResult<ColdStartSignedTimeV23> {
        let urls = funding
            .urls()
            .iter()
            .map(|url| -> ColdStartResult<std::net::SocketAddr> {
                Ok(url
                    .strip_prefix("http://")
                    .ok_or("local XMR scheme")?
                    .parse()?)
            })
            .collect::<ColdStartResult<Vec<_>>>()?;
        ColdStartSignedTimeV23::observe(self, node, bearer, urls, limits)
    }

    /// Materialize only this actor's public resources and authenticate first
    /// admission from the shared signed observation, never copied capabilities.
    pub(crate) fn prepare_mainnet_actor_v23(
        &self,
        actor: usize,
        node: crate::production_node::ProductionNodeConfigV1,
        funding: &RouteFundingOwnerV23,
        signed: &ColdStartSignedTimeV23,
        baseline: &NativeDomSnapshotV23,
        credentials: &NativeXmrDaemonCredentialsV23,
    ) -> ColdStartResult<(
        NativeXmrDaemonResourcesV23,
        crate::production_inputs::native_daemon_planning_v23::NativeDaemonPlanningContextV23,
    )> {
        let local = self.actor_id(actor)?;
        let urls = funding
            .urls()
            .iter()
            .map(|url| -> ColdStartResult<std::net::SocketAddr> {
                Ok(url
                    .strip_prefix("http://")
                    .ok_or("local XMR scheme")?
                    .parse()?)
            })
            .collect::<ColdStartResult<Vec<_>>>()?;
        let sockets = [funding.socket(0, actor)?, funding.socket(1, actor)?];
        let mut candidates = [None, None];
        for position in 0..2 {
            if self.terms[position].counterparty_leg.refund_to.0 == local {
                candidates[position] = Some(funding.raw(position)?);
            }
        }
        eprintln!("native preparation actor={actor}: preparing scoped resources");
        let resources = NativeXmrDaemonResourcesV23::prepare(
            self,
            actor,
            node,
            [urls.clone(), urls],
            [&sockets[0], &sockets[1]],
            candidates,
        )?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        eprintln!(
            "native preparation actor={actor}: resources ready; authenticating planning inputs"
        );
        let planning = self.prepare_authenticated(
            actor,
            resources.state_dir(),
            resources.paths(),
            self.signed_registry()?,
            signed.policy.clone(),
            signed.evidence.clone(),
            now,
        )?;
        eprintln!("native preparation actor={actor}: planning authenticated; preparing observed DOM wallet");
        self.prepare_dom_wallet_v23(
            actor,
            &resources,
            baseline,
            credentials
                .wallet_passphrases
                .get(actor)
                .ok_or("wallet actor")?,
        )?;
        eprintln!("native preparation actor={actor}: observed DOM wallet ready");
        Ok((resources, planning))
    }
}
