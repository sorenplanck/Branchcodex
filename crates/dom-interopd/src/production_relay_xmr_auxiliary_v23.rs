//! Deferred, exact Cancel/Compensation Relay ownership. No parent wire reuse.
use super::*;
use crate::production_contracts::{
    ProductionBootstrapRuntimeErrorV16, XmrAuxiliaryRelayOpenModeV23,
};
use crate::production_inputs::ProductionRosterLegV1;
use crate::relay_worker::UnavailableF6AuthorityV1;
use dom_scriptless_store::XmrGraphRecoverySigningEdgeV23;

pub(super) struct XmrAuxiliaryRelayProvisionerV23 {
    root: std::path::PathBuf,
    leg: LegIdV1,
    parent_wire: RouteWireContextV1,
    roster: ProductionRosterLegV1,
    registry: relay::auth::RosterRegistryV1,
    pins: ProductionRelayAuthorityPinsV6,
    secret: Zeroizing<[u8; 32]>,
}

pub(super) struct XmrAuxiliaryRelayOwnerV23 {
    pub(super) contracts: ProductionContractsV1<UnavailableF6AuthorityV1>,
    pub(super) wire: RouteWireContextV1,
    pub(super) chain: TrustedChainIdV1,
    pub(super) references: [SessionTransportIdentityReferenceV1; 2],
    pub(super) terms: [u8; 32],
}

impl XmrAuxiliaryRelayProvisionerV23 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        root: &Path,
        leg: LegIdV1,
        parent_wire: RouteWireContextV1,
        roster: ProductionRosterLegV1,
        registry: relay::auth::RosterRegistryV1,
        pins: ProductionRelayAuthorityPinsV6,
        secret: Zeroizing<[u8; 32]>,
        _startup_mode: ProductionRelayStage12ModeV1,
    ) -> Self {
        Self {
            root: root.to_owned(),
            leg,
            parent_wire,
            roster,
            registry,
            pins,
            secret,
        }
    }

    pub(super) fn open(
        &self,
        parent: &ProductionRelayStage12LegOwnerV1,
        binding: dom_actuator::DomSessionBindingV1,
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Result<XmrAuxiliaryRelayOwnerV23, ProductionBootstrapRuntimeErrorV16> {
        use ProductionBootstrapRuntimeErrorV16::Binding as Refused;
        if !matches!(
            edge,
            XmrGraphRecoverySigningEdgeV23::Cancel | XmrGraphRecoverySigningEdgeV23::Compensation
        ) || binding.session_id() == self.parent_wire.session_id
            || binding.route_id() != self.parent_wire.route_id
            || parent.wire != self.parent_wire
            || binding.chain_id() != *parent.trusted_chain_id.as_bytes()
        {
            return Err(Refused);
        }
        let local = self
            .roster
            .members
            .iter()
            .find(|entry| entry.participant_id.0 == binding.participant().participant_id())
            .ok_or(Refused)?;
        let remote = self
            .roster
            .members
            .iter()
            .find(|entry| entry.participant_id != local.participant_id)
            .ok_or(Refused)?;
        let wire = RouteWireContextV1 {
            session_id: binding.session_id(),
            ..self.parent_wire
        };
        let derive = |tag: u8, parent_id: [u8; 32]| {
            let mut bytes = b"DOM/XMR-SIGNING-RELAY-STORE/V23\0".to_vec();
            bytes.extend_from_slice(&[edge as u8, tag]);
            bytes.extend_from_slice(&parent_id);
            bytes.extend_from_slice(&self.parent_wire.session_id);
            bytes.extend_from_slice(&wire.session_id);
            *dom_crypto::blake2b_256(&bytes).as_bytes()
        };
        let mut pins = self.pins;
        let (sender_id, inbox_id, frames_id) = match self.leg {
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
        .map_err(|_| Refused)?;
        let inbox = DurableInboxConfigV1::new(
            inbox_id,
            pins.relay_database_id,
            wire,
            local.participant_id,
            pins.inbox_max_entries,
        )
        .map_err(|_| Refused)?;
        let frames = DurableFrameReassemblerConfigV2::new(
            frames_id,
            wire,
            local.participant_id,
            pins.frame_max_messages,
            pins.frame_max_active_bytes,
            pins.frame_max_active_chunks,
        )
        .map_err(|_| Refused)?;
        let config = RelayWorkerConfigV1::new_production_v6(sender, inbox, frames, pins, self.leg)
            .map_err(|_| Refused)?;
        let stem = format!(
            "xmr-signing-v23-{}-{:02x}-{}",
            hex::encode(wire.session_id),
            edge as u8,
            hex::encode(local.participant_id.0)
        );
        let roots = [
            self.root.join(format!("{stem}-sender")),
            self.root.join(format!("{stem}-inbox")),
            self.root.join(format!("{stem}-frames")),
        ];
        let mut present = 0;
        for root in &roots {
            match std::fs::symlink_metadata(root) {
                Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => present += 1,
                Ok(_) => return Err(Refused),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Refused),
            }
        }
        // The Store's resource tombstone, not startup mode, owns creation.
        // Ready always forces OpenExisting inside the authenticated factory.
        let mode = if present == 0 {
            XmrAuxiliaryRelayOpenModeV23::Create
        } else {
            XmrAuxiliaryRelayOpenModeV23::ResumeCreate
        };
        let paths = RelayWorkerPathsV1::new(&roots[0], &roots[1], &roots[2]);
        let contracts = parent
            .contracts
            .open_xmr_auxiliary_relay_v23(
                edge,
                &paths,
                config,
                self.registry.clone(),
                mode,
                *self.secret,
            )
            .map_err(|_| Refused)?;
        // The factory reauthenticates graph ancestry and exact identity refs;
        // derived transport identities equal the authenticated parent identities.
        Ok(XmrAuxiliaryRelayOwnerV23 {
            contracts,
            wire,
            chain: parent.trusted_chain_id,
            references: parent.noise_identity_references.clone(),
            terms: binding.terms_digest(),
        })
    }
}

fn edge_index(edge: XmrGraphRecoverySigningEdgeV23) -> Option<usize> {
    match edge {
        XmrGraphRecoverySigningEdgeV23::Cancel => Some(0),
        XmrGraphRecoverySigningEdgeV23::Compensation => Some(1),
        XmrGraphRecoverySigningEdgeV23::RefundAdaptor => None,
    }
}

impl ProductionRelayStage12OwnerV1 {
    pub(crate) fn xmr_signing_noise_scope_v23(
        &self,
        leg: LegIdV1,
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Option<(
        TrustedChainIdV1,
        RouteWireContextV1,
        [SessionTransportIdentityReferenceV1; 2],
        [u8; 32],
    )> {
        let leg = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        self.xmr_auxiliary_relays_v23[leg][edge_index(edge)?]
            .as_ref()
            .map(|owner| {
                (
                    owner.chain,
                    owner.wire,
                    owner.references.clone(),
                    owner.terms,
                )
            })
    }

    pub(crate) fn xmr_signing_and_relay_mut_v23(
        &mut self,
        leg: LegIdV1,
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Option<(
        &mut ProductionContractsV1<UnavailableF6AuthorityV1>,
        &mut ProductionRelayV1,
    )> {
        let leg = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        self.xmr_auxiliary_relays_v23[leg][edge_index(edge)?]
            .as_mut()
            .map(|owner| (&mut owner.contracts, &mut self.relay))
    }
}
