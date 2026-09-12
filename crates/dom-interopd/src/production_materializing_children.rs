//! Universal production child assembly from concrete live transaction owners
//! and scoped signer handles. No external plan or transaction bytes are imported.
//! The legacy root retains an explicit recovery-only Bitcoin variant until
//! it drives bilateral readiness and the post-anchor claim exchange.
use crate::production_child_btc::{
    ProductionBitcoinChildPortV1, ProductionBitcoinClaimMaterializationAuthorityV1,
    ProductionBitcoinFundingAuthorityV1, ProductionBitcoinMaterializationScopeV1,
    ProductionBitcoinPreparedClaimV11, SystemProductionBitcoinChildClockV1,
};
use crate::production_child_evm::{
    ProductionEvmChildPortV1, ProductionEvmMaterializingPortInputV1,
    SystemProductionEvmChildClockV1,
};
use crate::production_child_router::{
    AuthenticatedCounterpartyChildPortV4 as Port, AuthenticatedDomChildPortV1,
    ProductionSettlementChildRouterV1,
};
use crate::production_child_solana::{
    ProductionSolanaChildPortV1, ProductionSolanaMaterializationScopeV1, ScopedSolanaSignerV1,
    SystemProductionSolanaChildClockV1,
};
use crate::production_child_xmr::{
    ProductionXmrChildPortV1, ProductionXmrMaterializationScopeV1, ScopedXmrSweepAuthorityV1,
    SystemProductionXmrChildClockV1,
};
use crate::production_inputs::AuthenticatedProductionInputsV1;
use crate::production_route_topology::ProductionRouteTopologyV4;
use settlement_coordinator::{ChildAuthorityRefusalV1 as Error, SettlementFaceV1};

type EvmInput<'a> = ProductionEvmMaterializingPortInputV1<
    'a,
    evm_actuator::HttpEvmRpcV1,
    SystemProductionEvmChildClockV1,
>;

pub(crate) struct ProductionBitcoinChildInputV7 {
    pub(crate) actuator: btc_actuator::DurableBitcoinActuatorV1,
    pub(crate) rpc: btc_actuator::HttpBitcoinCoreRpcV1,
    pub(crate) lease: btc_actuator::BitcoinStorageLeaseStatusV1,
    pub(crate) funding: ProductionBitcoinFundingAuthorityV1,
    pub(crate) lease_renewal_ms_v12: Option<u64>,
}
pub(crate) struct ProductionSolanaChildInputV7 {
    pub(crate) actuator: solana_actuator::DurableSolanaActuatorV1,
    pub(crate) pool: solana_rpc_pool::SolanaRpcPool<solana_rpc::HttpSolanaRpc>,
    pub(crate) deployment: deployment_registry::ResolvedSolanaDeploymentV1,
    pub(crate) setup: solana_profile::ValidatedSolanaSetup,
    pub(crate) funder_lease: solana_actuator::SolanaActuatorLeaseV1,
    pub(crate) beneficiary_lease: solana_actuator::SolanaActuatorLeaseV1,
    pub(crate) funder_signer: Box<dyn ScopedSolanaSignerV1>,
    pub(crate) beneficiary_signer: Box<dyn ScopedSolanaSignerV1>,
    pub(crate) scope: ProductionSolanaMaterializationScopeV1,
    pub(crate) token_accounts:
        Option<crate::production_solana_signer::ProductionSolanaTokenAccountsV7>,
    pub(crate) lease_owner:
        Option<crate::production_universal_actuator::ProductionUniversalActuatorLeaseOwnerV11>,
}
pub(crate) struct ProductionXmrChildInputV7 {
    pub(crate) funding_window_v23: crate::production_timer::ProductionFundingWindowV23,
    pub(crate) actuator: std::rc::Rc<xmr_actuator::DurableXmrActuatorV1>,
    pub(crate) broadcast: xmr_rpc_broadcast_blocking::BlockingMoneroBroadcaster,
    pub(crate) observation: crate::production_children::QuorumXmrObservationPortV1,
    pub(crate) deployment: deployment_registry::ResolvedMoneroDeploymentV1,
    pub(crate) setup: xmr_setup_profile::ValidatedXmrSetup,
    pub(crate) lease: xmr_actuator::XmrActuatorLeaseV1,
    pub(crate) min_confirmations: u64,
    pub(crate) sweep: Box<dyn ScopedXmrSweepAuthorityV1>,
    pub(crate) scope: ProductionXmrMaterializationScopeV1,
    pub(crate) lease_owner:
        Option<crate::production_universal_actuator::ProductionUniversalActuatorLeaseOwnerV11>,
    pub(crate) recovery_driver_v12: Option<
        std::rc::Rc<crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12>,
    >,
    pub(crate) recovery_deferred_v23:
        Option<std::rc::Rc<crate::production_xmr_sweep::ProductionXmrDeferredRecoveryV23>>,
}

/// Each per-leg option owns its resources, including two independent owners
/// for same-family routes. Fresh Bitcoin construction accepts the retained
/// Store's genuine bilateral readiness, then installs M.8 after the anchors.
/// A scope, prepared refund alone or boolean never enables funding.
#[expect(
    dead_code,
    reason = "BTC fresh/SOL/XMR resource loaders still await generalized bootstrap"
)]
pub(crate) enum ProductionCounterpartyChildInputV7<'a> {
    Evm(Box<EvmInput<'a>>),
    Bitcoin {
        input: ProductionBitcoinChildInputV7,
        scope: ProductionBitcoinMaterializationScopeV1,
        claim: ProductionBitcoinClaimMaterializationAuthorityV1,
    },
    BitcoinPrefunding {
        input: ProductionBitcoinChildInputV7,
        scope: ProductionBitcoinMaterializationScopeV1,
        prepared: ProductionBitcoinPreparedClaimV11,
    },
    Solana(Box<ProductionSolanaChildInputV7>),
    Monero(Box<ProductionXmrChildInputV7>),
    BitcoinRetainedOnly(ProductionBitcoinChildInputV7),
}

impl ProductionCounterpartyChildInputV7<'_> {
    fn identity(&self) -> (SettlementFaceV1, [u8; 32]) {
        match self {
            Self::Evm(i) => (SettlementFaceV1::Evm, i.settlement.settlement_id.0),
            Self::Bitcoin { input, .. }
            | Self::BitcoinPrefunding { input, .. }
            | Self::BitcoinRetainedOnly(input) => {
                (SettlementFaceV1::Bitcoin, input.funding.settlement_id_v7())
            }
            Self::Solana(i) => (SettlementFaceV1::Solana, i.setup.settlement_id()),
            Self::Monero(i) => (SettlementFaceV1::Monero, i.setup.settlement_id()),
        }
    }
    fn construct(self) -> Result<Port, Error> {
        let result = match self {
            Self::Evm(input) => Port::Evm(ProductionSettlementChildRouterV1::authenticate_evm(
                ProductionEvmChildPortV1::new_materializing(*input)?,
            )),
            Self::Bitcoin {
                input: i,
                scope,
                claim,
            } => Port::Bitcoin(ProductionSettlementChildRouterV1::authenticate_bitcoin(
                ProductionBitcoinChildPortV1::new_materializing(
                    i.actuator,
                    i.rpc,
                    i.lease,
                    SystemProductionBitcoinChildClockV1,
                    i.funding,
                    scope,
                    claim,
                )?
                .with_lease_renewal_v12(i.lease_renewal_ms_v12)?,
            )),
            Self::BitcoinPrefunding {
                input: i,
                scope,
                prepared,
            } => Port::Bitcoin(ProductionSettlementChildRouterV1::authenticate_bitcoin(
                ProductionBitcoinChildPortV1::new_prefunding_v11(
                    i.actuator,
                    i.rpc,
                    i.lease,
                    SystemProductionBitcoinChildClockV1,
                    i.funding,
                    scope,
                    prepared,
                )?
                .with_lease_renewal_v12(i.lease_renewal_ms_v12)?,
            )),
            Self::BitcoinRetainedOnly(i) => {
                Port::Bitcoin(ProductionSettlementChildRouterV1::authenticate_bitcoin(
                    ProductionBitcoinChildPortV1::new(
                        i.actuator,
                        i.rpc,
                        i.lease,
                        SystemProductionBitcoinChildClockV1,
                        i.funding,
                    )?
                    .with_lease_renewal_v12(i.lease_renewal_ms_v12)?,
                ))
            }
            Self::Solana(i) => {
                let mut port = ProductionSolanaChildPortV1::new_materializing(
                    i.actuator,
                    i.pool,
                    i.deployment,
                    i.setup,
                    i.funder_lease,
                    i.beneficiary_lease,
                    SystemProductionSolanaChildClockV1,
                    i.funder_signer,
                    i.beneficiary_signer,
                    i.scope,
                )?
                .with_token_accounts_v7(i.token_accounts)?;
                if let Some(owner) = i.lease_owner {
                    port = port.with_lease_owner_v11(owner)?;
                }
                Port::Solana(ProductionSettlementChildRouterV1::authenticate_solana(port))
            }
            Self::Monero(i) => {
                let mut port = ProductionXmrChildPortV1::new_materializing(
                    i.actuator,
                    i.broadcast,
                    i.observation,
                    i.deployment,
                    i.setup,
                    i.lease,
                    i.min_confirmations,
                    SystemProductionXmrChildClockV1,
                    i.sweep,
                    i.scope,
                )?
                .with_funding_window_v23(i.funding_window_v23)?;
                if let Some(owner) = i.lease_owner {
                    port = port.with_lease_owner_v11(owner)?;
                }
                if let Some(driver) = i.recovery_driver_v12 {
                    port = port.with_recovery_driver_v12(driver)?;
                }
                if let Some(slot) = i.recovery_deferred_v23 {
                    port = port.with_deferred_recovery_v23(slot)?;
                }
                Port::Monero(ProductionSettlementChildRouterV1::authenticate_monero(port))
            }
        };
        Ok(result)
    }
}

pub(crate) fn compose_materializing_route_children_v7(
    inputs: &AuthenticatedProductionInputsV1,
    dom: AuthenticatedDomChildPortV1,
    upstream: ProductionCounterpartyChildInputV7<'_>,
    downstream: ProductionCounterpartyChildInputV7<'_>,
) -> Result<ProductionSettlementChildRouterV1, Error> {
    let topology = ProductionRouteTopologyV4::authenticate(inputs)?;
    require_identities(&topology, [upstream.identity(), downstream.identity()])?;
    // Constructors cannot broadcast. All shape/position checks above happen
    // before either exact owner's constructor can read or mutate custody.
    let upstream = upstream.construct()?;
    let downstream = downstream.construct()?;
    ProductionSettlementChildRouterV1::new_for_route_v4(inputs, dom, upstream, downstream)
}

fn require_identities(
    topology: &ProductionRouteTopologyV4,
    identities: [(SettlementFaceV1, [u8; 32]); 2],
) -> Result<(), Error> {
    topology.validate()?;
    for (index, (face, settlement_id)) in identities.into_iter().enumerate() {
        if face != topology.legs[index].face || settlement_id != topology.legs[index].settlement_id
        {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_route_topology::ProductionLegTopologyV4;
    const FAMILIES: [SettlementFaceV1; 4] = [
        SettlementFaceV1::Evm,
        SettlementFaceV1::Bitcoin,
        SettlementFaceV1::Solana,
        SettlementFaceV1::Monero,
    ];
    fn topology(a: SettlementFaceV1, b: SettlementFaceV1) -> ProductionRouteTopologyV4 {
        let leg = |face, settlement, chain| ProductionLegTopologyV4 {
            settlement_id: [settlement; 32],
            face,
            chain_id: [chain; 32],
            profile_digest: [40; 32],
            deployment_digest: [41; 32],
        };
        ProductionRouteTopologyV4 {
            route_id: [1; 32],
            composition_digest: [2; 32],
            dom_chain_id: [3; 32],
            terms_digest: [4; 32],
            registry_digest: [5; 32],
            dom_profile_digest: [6; 32],
            dom_deployment_digest: [7; 32],
            legs: [leg(a, 31, 11), leg(b, 32, if a == b { 11 } else { 12 })],
        }
    }
    #[test]
    fn v7_constructor_routes_all_sixteen_ordered_identity_pairs() {
        for a in FAMILIES {
            for b in FAMILIES {
                let topology = topology(a, b);
                assert!(require_identities(&topology, [(a, [31; 32]), (b, [32; 32])]).is_ok());
                assert!(require_identities(&topology, [(a, [32; 32]), (b, [31; 32])]).is_err());
                for wrong in FAMILIES.into_iter().filter(|v| *v != a) {
                    assert!(
                        require_identities(&topology, [(wrong, [31; 32]), (b, [32; 32])]).is_err()
                    );
                }
            }
        }
    }
    #[test]
    fn v7_constructor_refuses_reused_settlement_or_dom_as_counterparty() {
        let mut topology = topology(SettlementFaceV1::Bitcoin, SettlementFaceV1::Bitcoin);
        topology.legs[1].settlement_id = topology.legs[0].settlement_id;
        assert!(require_identities(&topology, [(SettlementFaceV1::Bitcoin, [31; 32]); 2]).is_err());
        let topology = self::topology(SettlementFaceV1::Dom, SettlementFaceV1::Evm);
        assert!(require_identities(
            &topology,
            [
                (SettlementFaceV1::Dom, [31; 32]),
                (SettlementFaceV1::Evm, [32; 32])
            ]
        )
        .is_err());
    }
}
