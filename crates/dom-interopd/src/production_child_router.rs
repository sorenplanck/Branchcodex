//! Face-exact routing from the settlement coordinator to production actuators.
//!
//! The coordinator persists every call before this boundary.  This module
//! performs no signing, RPC or evidence synthesis itself; it only prevents a
//! request for one authenticated face from reaching another face's authority.

#[cfg(test)]
#[path = "production_route_router_tests.rs"]
mod route_tests_v4;

use settlement_coordinator::{
    ChildAuthorityRefusalV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1,
    ChildObservationOutcomeV1, ChildObservationRequestV1, ChildReconciliationOutcomeV1,
    ChildReconciliationRequestV1, SettlementActionV1, SettlementChildAuthorityV1,
    SettlementChildObserverV1, SettlementChildPlanV1, SettlementFaceV1, SettlementLegV1,
};

use crate::production_route_topology::{leg_index_v4, ProductionRouteTopologyV4};
use route_composer::RouteScalar;

use crate::production_bitcoin_claim_driver::{
    BitcoinPostAnchorCallV11, BitcoinPostAnchorErrorV8, BitcoinPostAnchorExternalResourcesV11,
};
use crate::production_child_btc::{
    ProductionBitcoinChildClockV1, ProductionBitcoinChildPortV1,
    ProductionBitcoinPublicExtractionHandoffV1,
};
use crate::production_child_dom::{
    ProductionDomActionAuthorityV1, ProductionDomChildClockV1, ProductionDomChildPortV1,
};
use crate::production_child_evm::{ProductionEvmChildClockV1, ProductionEvmChildPortV1};
use crate::production_child_solana::{ProductionSolanaChildClockV1, ProductionSolanaChildPortV1};
use crate::production_child_xmr::{ProductionXmrChildClockV1, ProductionXmrChildPortV1};
use crate::production_contracts::ProductionContractsConsumedPostAnchorV2;
use btc_actuator::BitcoinRpcV1;
use evm_actuator::EvmRpcV1;

/// Complete public scope from which a chain authority may materialize one
/// exact retained child. No raw transaction or signer-selected fact crosses
/// this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionChildMaterializationRequestV1 {
    pub(crate) route_id: [u8; 32],
    pub(crate) effect_id: [u8; 32],
    pub(crate) settlement_id: [u8; 32],
    pub(crate) leg: SettlementLegV1,
    pub(crate) action: SettlementActionV1,
    pub(crate) fencing_epoch: u64,
    pub(crate) semantic_digest: [u8; 32],
    pub(crate) terms_digest: [u8; 32],
    pub(crate) registry_digest: [u8; 32],
    pub(crate) profile_digest: [u8; 32],
    pub(crate) deployment_digest: [u8; 32],
    pub(crate) route_scope_digest: [u8; 32],
    pub(crate) composition_digest: [u8; 32],
    pub(crate) role_plan_digest: [u8; 32],
    pub(crate) source_scope_digest: [u8; 32],
    /// Exact first-public-exposure evidence that authorized a public-secret
    /// child. Zero for non-secret and first-exposure requests.
    pub(crate) public_secret_evidence_digest: [u8; 32],
    pub(crate) exposure: settlement_coordinator::ChildExposureV1,
}

/// Immutable route scope that must authenticate an extraction handoff before
/// the Bitcoin child consumes its sole move-only capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionBitcoinExtractionHandoffScopeV1 {
    pub(crate) route_id: [u8; 32],
    pub(crate) composition_digest: [u8; 32],
    pub(crate) chain_id: [u8; 32],
    pub(crate) expected_txid: Option<[u8; 32]>,
    pub(crate) leg: SettlementLegV1,
    pub(crate) settlement_id: [u8; 32],
}

/// One chain-specific, owner-scoped production child authority.
///
/// Implementations own their durable actuator and RPC/signer boundaries. Raw
/// transactions and keys never cross this trait. A verified route scalar may
/// be borrowed only for a `UsesPublicSecret` claim after the parent route has
/// durably acknowledged the exact first-public-exposure evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProductionRetainedFundingIdV20 {
    Evm([u8; 32]),
    Solana(solana_types::SolanaSignature),
}

pub(crate) trait ProductionSettlementChildPortV1 {
    /// Exact public identity from this child's existing audited custody.
    /// None means no signed funding; it never means invalid retained evidence.
    fn retained_funding_id_v20(
        &mut self,
    ) -> Result<Option<ProductionRetainedFundingIdV20>, ChildAuthorityRefusalV1> {
        Err(ChildAuthorityRefusalV1::Refused)
    }

    /// The single chain face accepted by this authority.
    fn face(&self) -> SettlementFaceV1;

    /// Identity retained by a concrete single-settlement child. DOM may own
    /// both settlements; legacy test ports have no authenticated identity.
    fn settlement_id(&self) -> Option<[u8; 32]> {
        None
    }

    /// Renews a configured live actuator lease under its retained physical
    /// owner. It cannot take over an expired epoch or create a signing grant.
    fn renew_actuator_lease_v12(&mut self) -> Result<(), ChildAuthorityRefusalV1> {
        Ok(())
    }

    /// Reserves no nonce and reveals no scalar. A Bitcoin child freezes the
    /// actual action session and refuses claim execution until M.8 completes.
    fn prepare_bitcoin_claim_v11(
        &mut self,
        _request: ProductionChildMaterializationRequestV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        Err(ChildAuthorityRefusalV1::Refused)
    }

    /// Runs the retained Bitcoin child's late M.8 exchange. No other chain
    /// accepts this operation, and no raw actuator or signer can escape it.
    fn drive_bitcoin_post_anchor_v11(
        &mut self,
        _call: BitcoinPostAnchorCallV11,
        _resources: BitcoinPostAnchorExternalResourcesV11<'_, '_>,
    ) -> Result<Option<ProductionContractsConsumedPostAnchorV2>, BitcoinPostAnchorErrorV8> {
        Err(BitcoinPostAnchorErrorV8::Scope)
    }

    /// Prepares or reopens the exact transaction under this port's existing
    /// durable owner. The optional scalar is accepted only for an already
    /// public upstream claim and is never retained outside the actuator's
    /// opaque transaction custody.
    fn materialize(
        &mut self,
        request: ProductionChildMaterializationRequestV1,
        public_scalar: Option<&RouteScalar>,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1>;

    /// Idempotently progresses one already-journaled child call.
    fn externalize(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1>;

    /// Reconciles one pending call without dispatching different bytes.
    fn reconcile(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1>;

    /// Observes finality or invalidation for one exact child transaction.
    fn observe(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1>;

    /// Moves the sole post-materialization Bitcoin extraction owner out of the
    /// exact Bitcoin child. Other faces and non-fresh Bitcoin paths refuse.
    fn take_bitcoin_public_extraction_handoff(
        &mut self,
        _expected: ProductionBitcoinExtractionHandoffScopeV1,
    ) -> Result<ProductionBitcoinPublicExtractionHandoffV1, ChildAuthorityRefusalV1> {
        Err(ChildAuthorityRefusalV1::Refused)
    }

    /// Returns a handoff rejected by a downstream installer to the exact child
    /// that issued it, preserving retry without minting a second authority.
    fn restore_bitcoin_public_extraction_handoff(
        &mut self,
        _handoff: ProductionBitcoinPublicExtractionHandoffV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        Err(ChildAuthorityRefusalV1::Refused)
    }
}

pub(crate) struct AuthenticatedDomChildPortV1(Box<dyn ProductionSettlementChildPortV1>);
pub(crate) struct AuthenticatedEvmChildPortV1(Box<dyn ProductionSettlementChildPortV1>);
pub(crate) struct AuthenticatedBitcoinChildPortV1(Box<dyn ProductionSettlementChildPortV1>);
pub(crate) struct AuthenticatedSolanaChildPortV1(Box<dyn ProductionSettlementChildPortV1>);
pub(crate) struct AuthenticatedXmrChildPortV1(Box<dyn ProductionSettlementChildPortV1>);

/// Closed set of concrete counterparty owners. Same-family routes consume
/// two independent owners; no clone, shared signer or arbitrary trait import.
pub(crate) enum AuthenticatedCounterpartyChildPortV4 {
    Evm(AuthenticatedEvmChildPortV1),
    Bitcoin(AuthenticatedBitcoinChildPortV1),
    Solana(AuthenticatedSolanaChildPortV1),
    Monero(AuthenticatedXmrChildPortV1),
}

impl AuthenticatedCounterpartyChildPortV4 {
    fn into_port(self) -> Box<dyn ProductionSettlementChildPortV1> {
        match self {
            Self::Evm(AuthenticatedEvmChildPortV1(port))
            | Self::Bitcoin(AuthenticatedBitcoinChildPortV1(port))
            | Self::Solana(AuthenticatedSolanaChildPortV1(port))
            | Self::Monero(AuthenticatedXmrChildPortV1(port)) => port,
        }
    }
}

struct ProductionLegPortsV4 {
    topology: ProductionRouteTopologyV4,
    ports: [Box<dyn ProductionSettlementChildPortV1>; 2],
}

/// Exact face router owned by the production settlement bridge.
///
/// DOM is mandatory because every settlement plan contains one DOM child.
/// EVM and Bitcoin are optional independently so a deployment need not open
/// credentials for an unused counterparty chain. A request for an uninstalled
/// face fails closed; it is never redirected to the installed one.
pub(crate) struct ProductionSettlementChildRouterV1 {
    dom: Box<dyn ProductionSettlementChildPortV1>,
    by_leg: Option<ProductionLegPortsV4>,
    evm: Option<Box<dyn ProductionSettlementChildPortV1>>,
    bitcoin: Option<Box<dyn ProductionSettlementChildPortV1>>,
    monero: Option<Box<dyn ProductionSettlementChildPortV1>>,
    solana: Option<Box<dyn ProductionSettlementChildPortV1>>,
}

impl core::fmt::Debug for ProductionSettlementChildRouterV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSettlementChildRouterV1([authorities redacted])")
    }
}

impl ProductionSettlementChildRouterV1 {
    /// Visit every installed owner, including an idle route position. Idle
    /// children need their lease while the peer waits for chain confirmations.
    pub(crate) fn renew_actuator_leases_v12(&mut self) -> Result<(), ChildAuthorityRefusalV1> {
        self.dom.renew_actuator_lease_v12()?;
        if let Some(selected) = &mut self.by_leg {
            for port in &mut selected.ports {
                port.renew_actuator_lease_v12()?;
            }
        } else {
            for port in [
                &mut self.evm,
                &mut self.bitcoin,
                &mut self.monero,
                &mut self.solana,
            ]
            .into_iter()
            .flatten()
            {
                port.renew_actuator_lease_v12()?;
            }
        }
        Ok(())
    }

    /// Installs both independently scoped counterparties for any of the 16
    /// family pairs. Missing or reversed owners are rejected at construction.
    pub(crate) fn new_for_route_v4(
        inputs: &crate::production_inputs::AuthenticatedProductionInputsV1,
        dom: AuthenticatedDomChildPortV1,
        upstream: AuthenticatedCounterpartyChildPortV4,
        downstream: AuthenticatedCounterpartyChildPortV4,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        Self::from_leg_ports_v4(
            ProductionRouteTopologyV4::authenticate(inputs)?,
            dom.0,
            [upstream.into_port(), downstream.into_port()],
        )
    }

    fn from_leg_ports_v4(
        topology: ProductionRouteTopologyV4,
        dom: Box<dyn ProductionSettlementChildPortV1>,
        ports: [Box<dyn ProductionSettlementChildPortV1>; 2],
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        topology.validate()?;
        if dom.face() != SettlementFaceV1::Dom {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        for (port, binding) in ports.iter().zip(topology.legs) {
            if port.face() != binding.face || port.settlement_id() != Some(binding.settlement_id) {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
        }
        Ok(Self {
            dom,
            by_leg: Some(ProductionLegPortsV4 { topology, ports }),
            evm: None,
            bitcoin: None,
            solana: None,
            monero: None,
        })
    }

    pub(crate) fn new_with_all_counterparties(
        dom: AuthenticatedDomChildPortV1,
        evm: Option<AuthenticatedEvmChildPortV1>,
        bitcoin: Option<AuthenticatedBitcoinChildPortV1>,
        solana: Option<AuthenticatedSolanaChildPortV1>,
        monero: Option<AuthenticatedXmrChildPortV1>,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let AuthenticatedDomChildPortV1(dom) = dom;
        let evm = evm.map(|AuthenticatedEvmChildPortV1(port)| port);
        let bitcoin = bitcoin.map(|AuthenticatedBitcoinChildPortV1(port)| port);
        let solana = solana.map(|AuthenticatedSolanaChildPortV1(port)| port);
        let monero = monero.map(|AuthenticatedXmrChildPortV1(port)| port);
        if dom.face() != SettlementFaceV1::Dom
            || evm
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Evm)
            || bitcoin
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Bitcoin)
            || solana
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Solana)
            || monero
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Monero)
            || (evm.is_none() && bitcoin.is_none() && solana.is_none() && monero.is_none())
        {
            return Err(ChildAuthorityRefusalV1::Refused);
        }
        Ok(Self {
            dom,
            by_leg: None,
            evm,
            bitcoin,
            monero,
            solana,
        })
    }

    pub(crate) fn authenticate_dom<C, A>(
        port: ProductionDomChildPortV1<C, A>,
    ) -> AuthenticatedDomChildPortV1
    where
        C: ProductionDomChildClockV1 + 'static,
        A: ProductionDomActionAuthorityV1 + 'static,
    {
        AuthenticatedDomChildPortV1(Box::new(port))
    }

    pub(crate) fn authenticate_evm<R, C>(
        port: ProductionEvmChildPortV1<R, C>,
    ) -> AuthenticatedEvmChildPortV1
    where
        R: EvmRpcV1 + 'static,
        C: ProductionEvmChildClockV1 + 'static,
    {
        AuthenticatedEvmChildPortV1(Box::new(port))
    }

    pub(crate) fn authenticate_bitcoin<R, C>(
        port: ProductionBitcoinChildPortV1<R, C>,
    ) -> AuthenticatedBitcoinChildPortV1
    where
        R: BitcoinRpcV1 + 'static,
        C: ProductionBitcoinChildClockV1 + 'static,
    {
        AuthenticatedBitcoinChildPortV1(Box::new(port))
    }

    pub(crate) fn authenticate_solana<R, C>(
        port: ProductionSolanaChildPortV1<R, C>,
    ) -> AuthenticatedSolanaChildPortV1
    where
        R: solana_rpc::SolanaRpc + 'static,
        C: ProductionSolanaChildClockV1 + 'static,
    {
        AuthenticatedSolanaChildPortV1(Box::new(port))
    }

    pub(crate) fn authenticate_monero<B, O, C>(
        port: ProductionXmrChildPortV1<B, O, C>,
    ) -> AuthenticatedXmrChildPortV1
    where
        B: xmr_spend_port::ExactBroadcastPort + 'static,
        O: xmr_actuator::XmrObservationPortV1 + 'static,
        C: ProductionXmrChildClockV1 + 'static,
    {
        AuthenticatedXmrChildPortV1(Box::new(port))
    }

    #[cfg(test)]
    pub(crate) fn new_test(
        dom: Box<dyn ProductionSettlementChildPortV1>,
        evm: Option<Box<dyn ProductionSettlementChildPortV1>>,
        bitcoin: Option<Box<dyn ProductionSettlementChildPortV1>>,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if dom.face() != SettlementFaceV1::Dom
            || evm
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Evm)
            || bitcoin
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Bitcoin)
            || (evm.is_none() && bitcoin.is_none())
        {
            return Err(ChildAuthorityRefusalV1::Refused);
        }
        Ok(Self {
            dom,
            by_leg: None,
            evm,
            bitcoin,
            monero: None,
            solana: None,
        })
    }

    fn port(
        &mut self,
        face: SettlementFaceV1,
        leg: SettlementLegV1,
        route_id: [u8; 32],
        settlement_id: [u8; 32],
    ) -> Result<&mut (dyn ProductionSettlementChildPortV1 + '_), ChildAuthorityRefusalV1> {
        if let Some(scoped) = self.by_leg.as_mut() {
            scoped
                .topology
                .require_request(face, leg, route_id, settlement_id)?;
            return if face == SettlementFaceV1::Dom {
                Ok(self.dom.as_mut())
            } else {
                Ok(scoped.ports[leg_index_v4(leg)].as_mut())
            };
        }
        match face {
            SettlementFaceV1::Dom => Ok(self.dom.as_mut()),
            SettlementFaceV1::Evm => match self.evm.as_mut() {
                Some(port) => Ok(port.as_mut()),
                None => Err(ChildAuthorityRefusalV1::Refused),
            },
            SettlementFaceV1::Bitcoin => match self.bitcoin.as_mut() {
                Some(port) => Ok(port.as_mut()),
                None => Err(ChildAuthorityRefusalV1::Refused),
            },
            // An uninstalled child refuses, exactly as an uninstalled EVM
            // or Bitcoin child does; nothing is ever redirected.
            SettlementFaceV1::Monero => match self.monero.as_mut() {
                Some(port) => Ok(port.as_mut()),
                None => Err(ChildAuthorityRefusalV1::Refused),
            },
            SettlementFaceV1::Solana => match self.solana.as_mut() {
                Some(port) => Ok(port.as_mut()),
                None => Err(ChildAuthorityRefusalV1::Refused),
            },
        }
    }

    pub(crate) fn retained_funding_id_v20(
        &mut self,
        face: SettlementFaceV1,
        leg: SettlementLegV1,
        route_id: [u8; 32],
        settlement_id: [u8; 32],
    ) -> Result<Option<ProductionRetainedFundingIdV20>, ChildAuthorityRefusalV1> {
        if !matches!(face, SettlementFaceV1::Evm | SettlementFaceV1::Solana) {
            return Err(ChildAuthorityRefusalV1::Refused);
        }
        let port = self.port(face, leg, route_id, settlement_id)?;
        if port.face() != face || port.settlement_id() != Some(settlement_id) {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.retained_funding_id_v20()
    }

    pub(crate) fn prepare_bitcoin_claim_v11(
        &mut self,
        request: ProductionChildMaterializationRequestV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        if let Some(scoped) = self.by_leg.as_ref() {
            scoped
                .topology
                .require_admission_scope(request.terms_digest, request.registry_digest)?;
            if request.composition_digest != scoped.topology.composition_digest {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
        }
        let port = self.port(
            SettlementFaceV1::Bitcoin,
            request.leg,
            request.route_id,
            request.settlement_id,
        )?;
        if port.face() != SettlementFaceV1::Bitcoin
            || port.settlement_id() != Some(request.settlement_id)
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.prepare_bitcoin_claim_v11(request)
    }

    /// Keeps the late claim path reachable after the child's funding has run
    /// through the same boxed router. Exact route position selects the owner;
    /// BTC→DOM→BTC never borrows the other Bitcoin participant or actuator.
    pub(crate) fn drive_bitcoin_post_anchor_v11(
        &mut self,
        leg: SettlementLegV1,
        call: BitcoinPostAnchorCallV11,
        resources: BitcoinPostAnchorExternalResourcesV11<'_, '_>,
    ) -> Result<Option<ProductionContractsConsumedPostAnchorV2>, BitcoinPostAnchorErrorV8> {
        let expected_participant_leg = match leg {
            SettlementLegV1::Upstream => route_executor::LegIdV1::Upstream,
            SettlementLegV1::Downstream => route_executor::LegIdV1::Downstream,
        };
        if resources.participant.leg() != expected_participant_leg {
            return Err(BitcoinPostAnchorErrorV8::Scope);
        }
        if let Some(scoped) = self.by_leg.as_ref() {
            if scoped.topology.composition_digest != call.composition_digest {
                return Err(BitcoinPostAnchorErrorV8::Scope);
            }
        }
        let port = self
            .port(
                SettlementFaceV1::Bitcoin,
                leg,
                call.route_id,
                call.settlement_id,
            )
            .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?;
        if port.face() != SettlementFaceV1::Bitcoin
            || port.settlement_id() != Some(call.settlement_id)
        {
            return Err(BitcoinPostAnchorErrorV8::Scope);
        }
        port.drive_bitcoin_post_anchor_v11(call, resources)
    }

    pub(crate) fn materialize_child(
        &mut self,
        face: SettlementFaceV1,
        request: ProductionChildMaterializationRequestV1,
        public_scalar: Option<&RouteScalar>,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        if let Some(scoped) = self.by_leg.as_ref() {
            scoped
                .topology
                .require_admission_scope(request.terms_digest, request.registry_digest)?;
            if request.composition_digest != scoped.topology.composition_digest {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
            let chain_id = if face == SettlementFaceV1::Dom {
                scoped.topology.dom_chain_id
            } else {
                scoped.topology.legs[leg_index_v4(request.leg)].chain_id
            };
            scoped.topology.require_chain_binding(
                face,
                request.leg,
                chain_id,
                request.profile_digest,
                request.deployment_digest,
            )?;
        }
        let port = self.port(face, request.leg, request.route_id, request.settlement_id)?;
        if port.face() != face {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.materialize(request, public_scalar)
    }

    pub(crate) fn take_bitcoin_public_extraction_handoff(
        &mut self,
        expected: ProductionBitcoinExtractionHandoffScopeV1,
    ) -> Result<ProductionBitcoinPublicExtractionHandoffV1, ChildAuthorityRefusalV1> {
        if let Some(scoped) = self.by_leg.as_ref() {
            let binding = scoped.topology.legs[leg_index_v4(expected.leg)];
            if expected.chain_id != binding.chain_id
                || expected.composition_digest != scoped.topology.composition_digest
            {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
        }
        let port = self.port(
            SettlementFaceV1::Bitcoin,
            expected.leg,
            expected.route_id,
            expected.settlement_id,
        )?;
        if port.face() != SettlementFaceV1::Bitcoin {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.take_bitcoin_public_extraction_handoff(expected)
    }

    pub(crate) fn restore_bitcoin_public_extraction_handoff(
        &mut self,
        handoff: ProductionBitcoinPublicExtractionHandoffV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let port = self.port(
            SettlementFaceV1::Bitcoin,
            handoff.leg(),
            handoff.route_id(),
            handoff.settlement_id(),
        )?;
        if port.face() != SettlementFaceV1::Bitcoin {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.restore_bitcoin_public_extraction_handoff(handoff)
    }
}

impl SettlementChildAuthorityV1 for ProductionSettlementChildRouterV1 {
    fn externalize_child(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        let expected = request.face();
        if let Some(scoped) = self.by_leg.as_ref() {
            scoped
                .topology
                .require_admission_scope(request.terms_digest(), request.registry_digest())?;
            scoped.topology.require_chain_binding(
                expected,
                request.leg(),
                request.chain_id(),
                request.profile_digest(),
                request.deployment_digest(),
            )?;
        }
        let port = self.port(
            expected,
            request.leg(),
            request.route_id(),
            request.settlement_id(),
        )?;
        if port.face() != expected {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.externalize(request)
    }

    fn reconcile_child(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        let expected = request.dispatch.face();
        if let Some(scoped) = self.by_leg.as_ref() {
            scoped.topology.require_admission_scope(
                request.dispatch.terms_digest(),
                request.dispatch.registry_digest(),
            )?;
            scoped.topology.require_chain_binding(
                expected,
                request.dispatch.leg(),
                request.dispatch.chain_id(),
                request.dispatch.profile_digest(),
                request.dispatch.deployment_digest(),
            )?;
        }
        let port = self.port(
            expected,
            request.dispatch.leg(),
            request.dispatch.route_id(),
            request.dispatch.settlement_id(),
        )?;
        if port.face() != expected {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.reconcile(request)
    }
}

impl SettlementChildObserverV1 for ProductionSettlementChildRouterV1 {
    fn observe_child(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        let expected = request.face;
        if let Some(scoped) = self.by_leg.as_ref() {
            scoped
                .topology
                .require_admission_scope(request.terms_digest, request.registry_digest)?;
            scoped.topology.require_chain_binding(
                expected,
                request.leg,
                request.chain_id,
                request.profile_digest,
                request.deployment_digest,
            )?;
        }
        let port = self.port(
            expected,
            request.leg,
            request.route_id,
            request.settlement_id,
        )?;
        if port.face() != expected {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.observe(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RefusingPort(SettlementFaceV1);

    impl ProductionSettlementChildPortV1 for RefusingPort {
        fn face(&self) -> SettlementFaceV1 {
            self.0
        }

        fn materialize(
            &mut self,
            _request: ProductionChildMaterializationRequestV1,
            _public_scalar: Option<&RouteScalar>,
        ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
            Err(ChildAuthorityRefusalV1::Refused)
        }

        fn externalize(
            &mut self,
            _request: &ChildDispatchRequestV1,
        ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
            Err(ChildAuthorityRefusalV1::Refused)
        }

        fn reconcile(
            &mut self,
            _request: &ChildReconciliationRequestV1,
        ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
            Err(ChildAuthorityRefusalV1::Refused)
        }

        fn observe(
            &mut self,
            _request: &ChildObservationRequestV1,
        ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
            Err(ChildAuthorityRefusalV1::Refused)
        }
    }

    fn port(face: SettlementFaceV1) -> Box<dyn ProductionSettlementChildPortV1> {
        Box::new(RefusingPort(face))
    }

    #[test]
    fn construction_requires_dom_and_one_exact_counterparty_face() {
        assert!(ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Dom),
            Some(port(SettlementFaceV1::Evm)),
            None,
        )
        .is_ok());
        assert!(ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Dom),
            None,
            Some(port(SettlementFaceV1::Bitcoin)),
        )
        .is_ok());
        assert!(ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Dom),
            None,
            None,
        )
        .is_err());
        assert!(ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Evm),
            Some(port(SettlementFaceV1::Evm)),
            None,
        )
        .is_err());
        assert!(ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Dom),
            Some(port(SettlementFaceV1::Bitcoin)),
            None,
        )
        .is_err());
    }

    #[test]
    fn debug_never_enumerates_installed_authorities() {
        let router = ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Dom),
            Some(port(SettlementFaceV1::Evm)),
            Some(port(SettlementFaceV1::Bitcoin)),
        )
        .expect("valid router");
        assert_eq!(
            format!("{router:?}"),
            "ProductionSettlementChildRouterV1([authorities redacted])"
        );
    }
}
