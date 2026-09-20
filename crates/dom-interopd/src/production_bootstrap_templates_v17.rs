//! Wallet-offer mailbox and the native bilateral template-commit scheduler.
//!
//! Mailbox bytes are untrusted construction candidates, never signer permits.
//! Both daemons independently build the same native transactions and sign the
//! existing DSC1 0x0b commitments through the Contracts identity owner. The
//! V18 child then drives the native ordinary refund signer and final 0x10.
//! No adaptor signature or funding gate is synthesized by this scheduler.
//! The file mailbox requires an operator/transport to copy
//! public `.local` bytes to the peer's `.peer` name atomically.
use super::*;
use dom_adaptor::{
    DomBootstrapBudgetV17, DomBootstrapOfferV17, DomBootstrapProvenOfferV18,
    DomBootstrapTemplatesV17, VerifiedSharedOutputV1, DOM_NATIVE_BOOTSTRAP_POLICY_V17,
};
use dom_consensus::TransactionOutput;
use dom_crypto::pedersen::Commitment;
use kaystra_core::{
    types::{LockMechanism, TimelockSpec as TermsTimelock},
    SettlementTermsV1,
};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

type Error = ProductionBootstrapRuntimeErrorV16;
type Step = ProductionBootstrapStepV16;
#[path = "production_bootstrap_refund_v18.rs"]
mod refund_v18;

pub(super) struct TemplateDriverV17 {
    binding: DomSessionBindingV1,
    budget: DomBootstrapBudgetV17,
    terms: SettlementTermsV1,
    funder: usize,
    refund_height: u64,
    negotiated_tip: u64,
    directory: PathBuf,
    local_path: PathBuf,
    peer_path: PathBuf,
    // Public templates only. Rebuilt and reauthenticated after each restart.
    templates: Option<DomBootstrapTemplatesV17>,
    // Closed tag of the last fallible region this driver entered. It names a
    // step, never a value, a path or a credential, and exists so a refusal in
    // this phase reports where it fell instead of one opaque phase name.
    step_tag_v25: &'static str,
}

impl TemplateDriverV17 {
    /// The last fallible region entered by [`Self::step`].
    pub(super) const fn step_tag_v25(&self) -> &'static str {
        self.step_tag_v25
    }

    pub(super) fn publish_local(
        &self,
        material: &ProductionBoundDomSharedOutputV12,
    ) -> Result<(), Error> {
        let bytes = material
            .runtime_public_record_v16(b"wallet-key-proofs-v18")?
            .ok_or(Error::Binding)?;
        let offer = DomBootstrapProvenOfferV18::from_bytes(&bytes).map_err(|_| Error::Binding)?;
        self.require_offer(offer.offer(), self.binding.participant().participant_id())?;
        publish_exact(&self.directory, &self.local_path, &bytes)
    }
    pub(super) fn new(
        binding: DomSessionBindingV1,
        terms: &SettlementTermsV1,
        directory: &Path,
        negotiated_tip: u64,
        statement: &BpStatementV1,
    ) -> Result<Self, Error> {
        if terms.policy_version != DOM_NATIVE_BOOTSTRAP_POLICY_V17
            || terms.dom_leg.mechanism != LockMechanism::DomAdaptor2of2
            || terms.terms_hash().map_err(|_| Error::Binding)? != binding.terms_digest()
            || terms.session_id.0 != binding.session_id()
            || terms.dom_leg.chain_id.0 != binding.chain_id()
            || terms.roster.map(|p| p.0).as_slice() != statement.participant_ids()
            || terms.dom_leg.beneficiary == terms.dom_leg.refund_to
        {
            return Err(Error::Binding);
        }
        let budget = DomBootstrapBudgetV17::new(terms.dom_leg.amount, terms.fee_limit.dom_max)
            .map_err(|_| Error::Binding)?;
        if statement.value_noms() != budget.shared_value() {
            return Err(Error::Binding);
        }
        let funder = terms
            .roster
            .iter()
            .position(|p| *p == terms.dom_leg.refund_to)
            .ok_or(Error::Binding)?;
        if terms.roster[1 - funder] != terms.dom_leg.beneficiary {
            return Err(Error::Binding);
        }
        let refund_height = match terms.dom_leg.deadline {
            TermsTimelock::BlockHeight { value } if value > negotiated_tip => value,
            _ => return Err(Error::Binding),
        };
        require_directory(directory)?;
        let stem = format!("dom-wallet-offer-v18-{}", hex(&binding.session_id()));
        Ok(Self {
            binding,
            budget,
            terms: terms.clone(),
            funder,
            refund_height,
            negotiated_tip,
            directory: directory.to_owned(),
            local_path: directory.join(format!("{stem}.local")),
            peer_path: directory.join(format!("{stem}.peer")),
            templates: None,
            step_tag_v25: "templates_v17/entered",
        })
    }

    pub(super) fn step<F: F6TransportPortV1>(
        &mut self,
        owner: &mut ProductionContractsV1<F>,
        material: &mut ProductionBoundDomSharedOutputV12,
        chain: TrustedChainIdV1,
        statement: &BpStatementV1,
        now: u64,
    ) -> Result<Step, Error> {
        self.step_tag_v25 = "templates_v17/local_publish";
        owner
            .validate_dom_binding(self.binding)
            .map_err(|_| Error::Binding)?;
        require_directory(&self.directory)?;
        let local_bytes = material
            .runtime_public_record_v16(b"wallet-key-proofs-v18")?
            .ok_or(Error::Binding)?;
        let local =
            DomBootstrapProvenOfferV18::from_bytes(&local_bytes).map_err(|_| Error::Binding)?;
        self.require_offer(local.offer(), self.binding.participant().participant_id())?;
        publish_exact(&self.directory, &self.local_path, &local_bytes)?;
        self.step_tag_v25 = "templates_v17/peer_wait";
        let candidate = read_optional(&self.peer_path)?;
        let retained = material.runtime_public_record_v16(b"peer-wallet-key-proofs-v18")?;
        let peer_bytes = match (retained, candidate) {
            (Some(old), Some(new)) if old != new => return Err(Error::Binding),
            (Some(old), _) => old,
            (None, Some(new)) => new,
            (None, None) => return replay_bp_while_waiting(owner, material, now),
        };
        self.step_tag_v25 = "templates_v17/peer_verify";
        let peer =
            DomBootstrapProvenOfferV18::from_bytes(&peer_bytes).map_err(|_| Error::Binding)?;
        let local_index = usize::from(self.binding.participant().protocol_index());
        self.require_offer(peer.offer(), statement.participant_ids()[1 - local_index])?;
        local
            .verify(
                &chain,
                statement.participant_ids(),
                material.capability.binding().role(),
                local_index as u16,
            )
            .map_err(|_| Error::Binding)?;
        let peer_direction = match material.capability.binding().role() {
            DirectionV1::Initiator => DirectionV1::Responder,
            DirectionV1::Responder => DirectionV1::Initiator,
        };
        peer.verify(
            &chain,
            statement.participant_ids(),
            peer_direction,
            (1 - local_index) as u16,
        )
        .map_err(|_| Error::Binding)?;
        let proven_offers = if local_index == 0 {
            [local, peer]
        } else {
            [peer, local]
        };
        self.step_tag_v25 = "templates_v17/assemble";
        if self.templates.is_none() {
            let proof = owner
                .store
                .completed_operational_bp_proof_v16(
                    chain,
                    owner.session_id,
                    self.binding.terms_digest(),
                    statement,
                    &material.capsule,
                )?
                .ok_or(Error::Binding)?
                .into_proof();
            let commitment = statement.aggregate_commitment().to_compressed_bytes();
            let output = TransactionOutput::with_recovery_capsule(
                Commitment::from_compressed_bytes(&commitment).map_err(|_| Error::Crypto)?,
                proof.as_bytes().to_vec(),
                &material.capsule,
            )
            .map_err(|_| Error::Crypto)?;
            let shared = VerifiedSharedOutputV1::from_retained_output_v14(&output, &commitment)
                .map_err(|_| Error::Crypto)?;
            let offers = [
                proven_offers[0].offer().clone(),
                proven_offers[1].offer().clone(),
            ];
            let templates = DomBootstrapTemplatesV17::assemble(
                self.budget,
                statement,
                &shared,
                self.binding.terms_digest(),
                &offers,
                self.funder,
                self.refund_height,
                self.negotiated_tip,
            )
            .map_err(|_| Error::Binding)?;
            // Only freeze a peer candidate after all three balance equations
            // and proofs have passed. Retain before requesting any signature.
            material.retain_runtime_public_v16(b"peer-wallet-key-proofs-v18", &peer_bytes)?;
            self.templates = Some(templates);
        }
        self.step_tag_v25 = "templates_v17/authority";
        let templates = self.templates.as_ref().ok_or(Error::Binding)?;
        let authority = owner
            .store
            .prepare_operational_template_transport_authority(
                chain,
                owner.session_id,
                self.binding.terms_digest(),
                templates.funding.transaction_template(),
                templates.claim.transaction_template(),
                templates.refund.transaction_template(),
                statement,
                &material.capsule,
            )?;
        self.step_tag_v25 = "templates_v17/complete";
        let complete = owner.store.operational_templates_complete_v17(&authority)?;
        // Inspect the outbox before completing: the last locally accepted
        // commitment may still need its exact signed bytes retransmitted.
        self.step_tag_v25 = "templates_v17/outbox";
        let recovery = owner.store.resume_outbound_dsc1(owner.session_id)?;
        let bootstrap_pending = match &recovery {
            OutboundDsc1RecoveryV1::SigningRequest(request) => {
                (1..=0x0b).contains(&request.message_type())
            }
            OutboundDsc1RecoveryV1::Committed(record) => (1..=0x0b).contains(
                &(SignedMessageV1::decode_exact(record.signed_bytes())
                    .map_err(|_| Error::Binding)?
                    .unsigned()
                    .kind() as u8),
            ),
            OutboundDsc1RecoveryV1::None => false,
        };
        if complete {
            self.step_tag_v25 = "templates_v17/retain_keys";
            owner.store.retain_bootstrap_wallet_keys_v18(
                chain,
                owner.session_id,
                &self.terms,
                &proven_offers,
                self.negotiated_tip,
            )?;
            self.step_tag_v25 = "templates_v17/refund";
            if !bootstrap_pending {
                return refund_v18::step(
                    owner,
                    material,
                    self.binding,
                    chain,
                    templates,
                    &self.terms,
                    now,
                );
            }
            refund_v18::prepare_ingress(owner, chain, templates, &self.terms)?;
        } else {
            owner.refresh_reissued_contracts_ingress_v16(
                PreparedContractsIngressV1::operational_template(authority),
            )?;
        }
        self.step_tag_v25 = "templates_v17/stage";
        let expiry = ProductionBootstrapLegV16::expiry(material, now)?;
        match recovery {
            OutboundDsc1RecoveryV1::SigningRequest(request) => {
                if !bootstrap_pending || request.sender_id() != &owner.local_participant {
                    return Err(Error::Binding);
                }
                owner.sign_commit_and_stage(*request, expiry)?;
                Ok(Step::Staged)
            }
            OutboundDsc1RecoveryV1::Committed(record) => {
                if !bootstrap_pending || record.sender_id() != &owner.local_participant {
                    return Err(Error::Binding);
                }
                owner
                    .relay
                    .try_borrow_mut()
                    .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                    .stage_store_outbound_dsc1(*record, expiry)
                    .map_err(ProductionContractsOutboundErrorV1::Relay)?;
                Ok(Step::Staged)
            }
            OutboundDsc1RecoveryV1::None => {
                // Reissue the same immutable native authority after ingress
                // ownership transfer. The Store chooses whose turn it is.
                let authority = owner
                    .store
                    .prepare_operational_template_transport_authority(
                        chain,
                        owner.session_id,
                        self.binding.terms_digest(),
                        templates.funding.transaction_template(),
                        templates.claim.transaction_template(),
                        templates.refund.transaction_template(),
                        statement,
                        &material.capsule,
                    )?;
                if let Some(request) = owner
                    .store
                    .prepare_template_commit_dsc1_signing_request(&authority)?
                {
                    owner.sign_commit_and_stage(request, expiry)?;
                    Ok(Step::Staged)
                } else {
                    Ok(Step::AwaitingPeer)
                }
            }
        }
    }

    fn require_offer(
        &self,
        offer: &DomBootstrapOfferV17,
        participant: [u8; 32],
    ) -> Result<(), Error> {
        if offer.chain_id != self.binding.chain_id()
            || offer.session_id != self.binding.session_id()
            || offer.terms_hash != self.binding.terms_digest()
            || offer.participant_id != participant
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

fn replay_bp_while_waiting<F: F6TransportPortV1>(
    owner: &mut ProductionContractsV1<F>,
    material: &mut ProductionBoundDomSharedOutputV12,
    now: u64,
) -> Result<Step, Error> {
    match owner.store.resume_outbound_dsc1(owner.session_id)? {
        OutboundDsc1RecoveryV1::None => Ok(Step::AwaitingPeer),
        OutboundDsc1RecoveryV1::SigningRequest(request) => {
            if !(1..=10).contains(&request.message_type())
                || request.sender_id() != &owner.local_participant
            {
                return Err(Error::Binding);
            }
            let expiry = ProductionBootstrapLegV16::expiry(material, now)?;
            owner.sign_commit_and_stage(*request, expiry)?;
            Ok(Step::Staged)
        }
        OutboundDsc1RecoveryV1::Committed(record) => {
            let kind = SignedMessageV1::decode_exact(record.signed_bytes())
                .map_err(|_| Error::Binding)?
                .unsigned()
                .kind() as u8;
            if !(1..=10).contains(&kind) || record.sender_id() != &owner.local_participant {
                return Err(Error::Binding);
            }
            let expiry = ProductionBootstrapLegV16::expiry(material, now)?;
            owner
                .relay
                .try_borrow_mut()
                .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                .stage_store_outbound_dsc1(*record, expiry)
                .map_err(ProductionContractsOutboundErrorV1::Relay)?;
            Ok(Step::Staged)
        }
    }
}

fn require_directory(path: &Path) -> Result<(), Error> {
    let m = std::fs::symlink_metadata(path).map_err(|_| Error::Mailbox)?;
    if !path.is_absolute()
        || std::fs::canonicalize(path).ok().as_deref() != Some(path)
        || !m.is_dir()
        || m.file_type().is_symlink()
        || m.mode() & 0o7777 != 0o700
        || m.uid() != rustix::process::getuid().as_raw()
    {
        return Err(Error::Mailbox);
    }
    Ok(())
}
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Mailbox),
        Ok(_) => {}
    }
    // Present-but-unreadable/malformed is never reported as peer absence.
    crate::production_config::read_owner_file_bounded(
        path,
        DomBootstrapProvenOfferV18::MAX_BYTES as u64,
        crate::production_config::ProductionConfigErrorV1::InputArtifactUnavailable,
    )
    .map(Some)
    .map_err(|_| Error::Mailbox)
}
fn publish_exact(directory: &Path, path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(existing) = read_optional(path)? {
        return if existing == bytes {
            Ok(())
        } else {
            Err(Error::Binding)
        };
    }
    let mut suffix = [0; 16];
    getrandom::getrandom(&mut suffix).map_err(|_| Error::Mailbox)?;
    let temporary = directory.join(format!("dom-wallet-offer-v18-{}.pending", hex(&suffix)));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| Error::Mailbox)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| Error::Mailbox)?;
    // The root's state-directory owner excludes concurrent local producers.
    // Rename publishes complete public bytes; no private data enters the file.
    std::fs::rename(&temporary, path).map_err(|_| Error::Mailbox)?;
    std::fs::File::open(directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| Error::Mailbox)?;
    if read_optional(path)?.as_deref() != Some(bytes) {
        return Err(Error::Mailbox);
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 15) as usize] as char);
    }
    text
}
