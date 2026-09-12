//! Separate DSC1/Relay owner for output D. It has no F6 or funding authority.
use super::*;
use crate::production_contracts::{ProductionBootstrapLegV16, ProductionBootstrapRuntimeErrorV16};
use crate::production_contracts_bootstrap::producer_v13::MountedCancelledContractsV22;
use crate::production_dom_shared_bootstrap_v12::ProductionBoundDomSharedOutputV12;
use crate::relay_worker::UnavailableF6AuthorityV1;
use dom_scriptless_store::{ContractsSessionStoreV1, PreparedEarlyTransportAuthorityV1};

pub(super) struct PreparedCancelledRelayV22 {
    policy: xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
    parent_terms: [u8; 32],
    store: ContractsSessionStoreV1,
    early: PreparedEarlyTransportAuthorityV1,
    driver: ProductionBootstrapLegV16,
    paths: RelayWorkerPathsV1,
    config: RelayWorkerConfigV1,
    rosters: relay::auth::RosterRegistryV1,
    wire: RouteWireContextV1,
    chain: TrustedChainIdV1,
    references: [SessionTransportIdentityReferenceV1; 2],
}

pub(super) struct CancelledRelayOwnerV22 {
    pub(super) policy: xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
    pub(super) parent_terms: [u8; 32],
    pub(super) contracts: ProductionContractsV1<UnavailableF6AuthorityV1>,
    pub(super) driver: ProductionBootstrapLegV16,
    pub(super) wire: RouteWireContextV1,
    pub(super) chain: TrustedChainIdV1,
    pub(super) references: [SessionTransportIdentityReferenceV1; 2],
}

impl CancelledRelayOwnerV22 {
    pub(super) fn step(
        &mut self,
        material: &mut ProductionBoundDomSharedOutputV12,
        now: u64,
    ) -> Result<(), ProductionBootstrapRuntimeErrorV16> {
        self.driver.step(&mut self.contracts, material, now)?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare(
    leg: LegIdV1,
    mut mounted: MountedCancelledContractsV22,
    material: &ProductionBoundDomSharedOutputV12,
    parent: dom_actuator::DomSessionBindingV1,
    chain: TrustedChainIdV1,
    inputs: &AuthenticatedProductionInputsV1,
    mut pins: ProductionRelayAuthorityPinsV6,
) -> Result<PreparedCancelledRelayV22, ProductionRelayStage12ErrorV1> {
    use ProductionRelayStage12ErrorV1::{ContractsRefused, InvalidBinding};
    let index = match leg {
        LegIdV1::Upstream => 0,
        LegIdV1::Downstream => 1,
    };
    if mounted.roster != inputs.roster_bundle().legs()[index] {
        return Err(InvalidBinding);
    }
    let driver = ProductionBootstrapLegV16::for_xmr_cancelled_v22(
        parent,
        chain,
        mounted.roster,
        &mounted.policy,
        material,
    )
    .map_err(|_| InvalidBinding)?;
    let binding = parent
        .for_xmr_cancelled_output_v22()
        .map_err(|_| InvalidBinding)?;
    let local_index = usize::from(parent.participant().protocol_index());
    let local = mounted.roster.members[local_index];
    let remote = mounted.roster.members[local_index ^ 1];
    let wire = RouteWireContextV1 {
        network_id: inputs.roster_bundle().network_id(),
        route_id: parent.route_id(),
        session_id: binding.session_id(),
        roster_snapshot: mounted.roster.roster_snapshot,
        policy_version: mounted.roster.policy_version,
    };
    // Separate native sender/inbox/frame identities, derived from the pinned
    // parent identity and exact D session. Never reuse the C transport stores.
    let derive = |tag: u8, parent_id: [u8; 32]| {
        let mut bytes = b"DOM/XMR-D-RELAY-STORE/V22\0".to_vec();
        bytes.push(tag);
        bytes.extend_from_slice(&parent_id);
        bytes.extend_from_slice(&binding.session_id());
        *dom_crypto::blake2b_256(&bytes).as_bytes()
    };
    let (sender_id, inbox_id, frames_id) = match leg {
        LegIdV1::Upstream => {
            pins.upstream_sender_store_id = derive(1, pins.upstream_sender_store_id);
            pins.upstream_inbox_id = derive(2, pins.upstream_inbox_id);
            pins.upstream_reassembler_id = derive(3, pins.upstream_reassembler_id);
            (
                pins.upstream_sender_store_id,
                pins.upstream_inbox_id,
                pins.upstream_reassembler_id,
            )
        }
        LegIdV1::Downstream => {
            pins.downstream_sender_store_id = derive(1, pins.downstream_sender_store_id);
            pins.downstream_inbox_id = derive(2, pins.downstream_inbox_id);
            pins.downstream_reassembler_id = derive(3, pins.downstream_reassembler_id);
            (
                pins.downstream_sender_store_id,
                pins.downstream_inbox_id,
                pins.downstream_reassembler_id,
            )
        }
    };
    let sender = DurableRelaySenderConfigV1::new(
        sender_id,
        wire,
        local.participant_id,
        remote.participant_id,
        local.role,
        local.xonly_key,
        pins.sender_max_envelopes,
    )
    .map_err(|_| InvalidBinding)?;
    let inbox = DurableInboxConfigV1::new(
        inbox_id,
        pins.relay_database_id,
        wire,
        local.participant_id,
        pins.inbox_max_entries,
    )
    .map_err(|_| InvalidBinding)?;
    let frames = DurableFrameReassemblerConfigV2::new(
        frames_id,
        wire,
        local.participant_id,
        pins.frame_max_messages,
        pins.frame_max_active_bytes,
        pins.frame_max_active_chunks,
    )
    .map_err(|_| InvalidBinding)?;
    let config = RelayWorkerConfigV1::new_production_v6(sender, inbox, frames, pins, leg)
        .map_err(|_| InvalidBinding)?;
    let references = order_identity_references(
        mounted
            .store
            .transport_identity_references(binding.session_id())
            .map_err(|_| ContractsRefused)?,
        local.participant_id,
        remote.participant_id,
    )?;
    let slot = 2 * index + local_index;
    let paths = RelayWorkerPathsV1::new(
        mounted
            .work_dir
            .join(format!("cancelled-relay-sender-{slot}")),
        mounted
            .work_dir
            .join(format!("cancelled-relay-inbox-{slot}")),
        mounted
            .work_dir
            .join(format!("cancelled-relay-frames-{slot}")),
    );
    Ok(PreparedCancelledRelayV22 {
        policy: mounted.policy,
        parent_terms: parent.terms_digest(),
        store: mounted.store,
        early: mounted.early.take().ok_or(ContractsRefused)?,
        driver,
        paths,
        config,
        wire,
        chain,
        references,
        rosters: inputs.roster_registry().clone(),
    })
}

impl PreparedCancelledRelayV22 {
    pub(super) fn open(
        self,
        mode: AuthorityOpenModeV1,
        identity: Rc<ContractsTransportIdentityStoreV1>,
        relay_secret: &[u8; 32],
    ) -> Result<CancelledRelayOwnerV22, ProductionRelayStage12ErrorV1> {
        use ProductionRelayStage12ErrorV1::ContractsRefused;
        let mut contracts = match mode {
            AuthorityOpenModeV1::Create => ProductionContractsV1::create(
                self.store,
                identity,
                &self.paths,
                self.config,
                self.rosters,
                UnavailableF6AuthorityV1,
                *relay_secret,
            ),
            AuthorityOpenModeV1::ResumeCreate => ProductionContractsV1::resume_create_production(
                self.store,
                identity,
                &self.paths,
                self.config,
                self.rosters,
                UnavailableF6AuthorityV1,
                *relay_secret,
            ),
            AuthorityOpenModeV1::OpenExisting => ProductionContractsV1::open_existing(
                self.store,
                identity,
                &self.paths,
                self.config,
                self.rosters,
                UnavailableF6AuthorityV1,
                *relay_secret,
            ),
        }
        .map_err(|_| ContractsRefused)?;
        contracts
            .install_contracts_ingress(PreparedContractsIngressV1::early(self.early))
            .map_err(|_| ContractsRefused)?;
        Ok(CancelledRelayOwnerV22 {
            policy: self.policy,
            parent_terms: self.parent_terms,
            contracts,
            driver: self.driver,
            wire: self.wire,
            chain: self.chain,
            references: self.references,
        })
    }
}
