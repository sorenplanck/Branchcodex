//! Session-specific recovery Relay owners sharing the one physical Contracts Store.
use super::*;
use crate::relay_worker::UnavailableF6AuthorityV1;
use dom_scriptless_store::XmrGraphRecoverySigningEdgeV23;

pub(crate) enum XmrAuxiliaryRelayOpenModeV23 {
    Create,
    ResumeCreate,
    OpenExisting,
}

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    /// The configuration cannot select an arbitrary child: its session must
    /// have authenticated graph ancestry under this exact parent and route.
    /// Only the transport databases are separate; the native Store is not reopened.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_xmr_auxiliary_relay_v23(
        &self,
        edge: XmrGraphRecoverySigningEdgeV23,
        paths: &RelayWorkerPathsV1,
        config: RelayWorkerConfigV1,
        rosters: RosterRegistryV1,
        mode: XmrAuxiliaryRelayOpenModeV23,
        relay_signing_secret: [u8; 32],
    ) -> Result<ProductionContractsV1<UnavailableF6AuthorityV1>, ProductionContractsOpenErrorV1>
    {
        let wire = config.wire_context();
        if !config.is_production_v6_bound()
            || wire.route_id != self.route_id
            || wire.session_id == self.session_id
            || config.local_participant().0 != self.local_participant
            || config.remote_participant().0 != self.remote_participant
        {
            return Err(ProductionContractsOpenErrorV1::StoreRejected);
        }
        self.store.require_xmr_auxiliary_transport_scope_v23(
            self.session_id,
            self.route_id,
            wire.session_id,
            edge,
        )?;
        let relay_keys = validate_relay_roster(&rosters, &config)?;
        let local_protocol_index =
            validate_and_bind_identity(&self.store, &self.identity, &config, &relay_keys)?;
        let permit = self.store.prepare_xmr_graph_resource_v23(
            wire.session_id,
            edge,
            dom_scriptless_store::XmrGraphResourceKindV23::AuxiliaryRelay,
        )?;
        let mode = if permit.state() == dom_scriptless_store::XmrGraphResourceStateV23::Ready {
            XmrAuxiliaryRelayOpenModeV23::OpenExisting
        } else {
            mode
        };
        let store = Rc::clone(&self.store);
        let relay = match mode {
            XmrAuxiliaryRelayOpenModeV23::Create => DurableRelayWorkerV1::create(
                paths,
                config,
                Rc::clone(&store),
                rosters,
                UnavailableF6AuthorityV1,
                relay_signing_secret,
            ),
            XmrAuxiliaryRelayOpenModeV23::ResumeCreate => {
                DurableRelayWorkerV1::resume_create_production(
                    paths,
                    config,
                    Rc::clone(&store),
                    rosters,
                    UnavailableF6AuthorityV1,
                    relay_signing_secret,
                )
            }
            XmrAuxiliaryRelayOpenModeV23::OpenExisting => DurableRelayWorkerV1::open_existing(
                paths,
                config,
                Rc::clone(&store),
                rosters,
                UnavailableF6AuthorityV1,
                relay_signing_secret,
            ),
        }?;
        let mut owner = ProductionContractsV1 {
            session_id: wire.session_id,
            route_id: self.route_id,
            local_participant: self.local_participant,
            remote_participant: self.remote_participant,
            local_protocol_index,
            store,
            identity: Rc::clone(&self.identity),
            relay: Rc::new(RefCell::new(relay)),
            claim_owner_v21: Rc::new(RefCell::new(
                claim_owner_v21::ProductionClaimOwnerV21::default(),
            )),
            dom_child_store_authority_issued: Cell::new(false),
            dom_refund_face_issued: Cell::new(false),
            evm_remote_transport_authority_issued: Cell::new(false),
            xmr_remote_transport_authority_issued: Cell::new(false),
        };
        let ingress = owner
            .store
            .prepare_xmr_graph_signing_ingress_v23(wire.session_id, edge)?;
        owner
            .install_contracts_ingress(PreparedContractsIngressV1::xmr_graph_signing_v23(ingress))
            .map_err(|_| ProductionContractsOpenErrorV1::StoreRejected)?;
        self.store.mark_xmr_graph_resource_ready_v23(permit)?;
        Ok(owner)
    }
}
