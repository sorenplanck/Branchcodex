//! Native ordinary refund signing, durable finalization and DSC1 transport.
use super::*;
use crate::production_dom_claim_driver_v12::{
    prepare_next_dom_recovery_edge_with_signer_v12, ProductionDomClaimProgressV12,
};
use dom_adaptor::{ContractKindV1, PurposeV1};

pub(super) fn prepare_ingress<F: F6TransportPortV1>(
    owner: &mut ProductionContractsV1<F>,
    chain: TrustedChainIdV1,
    templates: &DomBootstrapTemplatesV17,
    terms: &SettlementTermsV1,
) -> Result<(), Error> {
    if terms.counterparty_leg.mechanism == LockMechanism::CrossCurveSharedSpend {
        return Err(Error::XmrRecoveryGraphRequired);
    }
    match owner
        .store
        .resume_operational_signing_session(chain, owner.session_id, PurposeV1::Refund)
    {
        Ok(_) => {}
        Err(SessionStoreError::SessionNotFound) => {
            let roster = owner.store.bootstrap_wallet_signing_roster_v18(
                chain,
                owner.session_id,
                PurposeV1::Refund,
            )?;
            owner.store.bind_operational_signing_session(
                chain,
                owner.session_id,
                ContractKindV1::WitnessOrTimeout,
                PurposeV1::Refund,
                roster,
                templates.refund.transaction_template().clone(),
                0,
                None,
            )?;
        }
        Err(error) => return Err(error.into()),
    }
    let transport = owner
        .store
        .prepare_operational_signing_transport_authority(
            chain,
            owner.session_id,
            PurposeV1::Refund,
        )?;
    owner.refresh_reissued_contracts_ingress_v16(
        PreparedContractsIngressV1::operational_signing(transport),
    )?;
    Ok(())
}

pub(super) fn step<F: F6TransportPortV1>(
    owner: &mut ProductionContractsV1<F>,
    material: &mut ProductionBoundDomSharedOutputV12,
    binding: DomSessionBindingV1,
    chain: TrustedChainIdV1,
    templates: &DomBootstrapTemplatesV17,
    terms: &SettlementTermsV1,
    now: u64,
) -> Result<Step, Error> {
    // Ordinary refund is the scripted-chain path. XMR's adaptor refund and
    // compensation graph must never be replaced by this plain transaction.
    if terms.counterparty_leg.mechanism == LockMechanism::CrossCurveSharedSpend {
        return Err(Error::XmrRecoveryGraphRequired);
    }
    let complete = owner
        .store
        .completed_bootstrap_refund_v18(chain, owner.session_id)?
        .is_some();
    if complete
        && owner
            .store
            .load_session(owner.session_id)?
            .irreversible()
            .funding_authorized
    {
        // 0x0c..0x0e are shared by Refund, Funding and ClaimAdaptor. After
        // funding authorization, a pending signing edge belongs to its later
        // native driver; bootstrap must not install Refund ingress over it.
        if let Some(signer) = material.refund_signer_v18.take() {
            if material.vault.is_some() {
                return Err(Error::Vault);
            }
            material.vault = Some(signer.into_vault_v18());
        }
        return Ok(Step::Complete);
    }
    let recovery = owner.store.resume_outbound_dsc1(owner.session_id)?;
    let pending_kind = match &recovery {
        OutboundDsc1RecoveryV1::SigningRequest(request) => Some(request.message_type()),
        OutboundDsc1RecoveryV1::Committed(record) => Some(
            SignedMessageV1::decode_exact(record.signed_bytes())
                .map_err(|_| Error::Binding)?
                .unsigned()
                .kind() as u8,
        ),
        OutboundDsc1RecoveryV1::None => None,
    };
    if complete && !pending_kind.is_some_and(|kind| (0x0c..=0x0e).contains(&kind) || kind == 0x10) {
        if let Some(signer) = material.refund_signer_v18.take() {
            if material.vault.is_some() {
                return Err(Error::Vault);
            }
            material.vault = Some(signer.into_vault_v18());
        }
        return Ok(Step::Complete);
    }
    let expiry = ProductionBootstrapLegV16::expiry(material, now)?;
    if complete {
        let authority = owner
            .store
            .prepare_operational_final_refund_transport_authority(chain, owner.session_id)?;
        owner.refresh_reissued_contracts_ingress_v16(
            PreparedContractsIngressV1::operational_final_refund(authority),
        )?;
        return replay(owner, recovery, expiry)?.ok_or(Error::Binding);
    }
    let accepted = match owner.store.resume_operational_signing_session(
        chain,
        owner.session_id,
        PurposeV1::Refund,
    ) {
        Ok(accepted) => accepted,
        Err(SessionStoreError::SessionNotFound) => {
            let roster = owner.store.bootstrap_wallet_signing_roster_v18(
                chain,
                owner.session_id,
                PurposeV1::Refund,
            )?;
            owner.store.bind_operational_signing_session(
                chain,
                owner.session_id,
                ContractKindV1::WitnessOrTimeout,
                PurposeV1::Refund,
                roster,
                templates.refund.transaction_template().clone(),
                0,
                None,
            )?
        }
        Err(error) => return Err(error.into()),
    };
    let prefix =
        dom_adaptor::AcceptedSigningSessionV1::accepted_signing_messages(&accepted).count();
    if prefix == 6 {
        let authority = owner
            .store
            .prepare_operational_final_refund_transport_authority(chain, owner.session_id)?;
        owner.refresh_reissued_contracts_ingress_v16(
            PreparedContractsIngressV1::operational_final_refund(authority),
        )?;
        if let Some(step) = replay(owner, recovery, expiry)? {
            return Ok(step);
        }
        let authority = owner
            .store
            .prepare_operational_final_refund_transport_authority(chain, owner.session_id)?;
        if let Some(request) = owner
            .store
            .prepare_final_refund_dsc1_signing_request(&authority)?
        {
            owner.sign_commit_and_stage(request, expiry)?;
            return Ok(Step::Staged);
        }
        return Ok(Step::AwaitingPeer);
    }
    let transport = owner
        .store
        .prepare_operational_signing_transport_authority(
            chain,
            owner.session_id,
            PurposeV1::Refund,
        )?;
    owner.refresh_reissued_contracts_ingress_v16(
        PreparedContractsIngressV1::operational_signing(transport),
    )?;
    if let Some(step) = replay(owner, recovery, expiry)? {
        return Ok(step);
    }
    if material.refund_signer_v18.is_none() {
        let vault = material.vault.take().ok_or(Error::Vault)?;
        let share = material.refund_share_v18.take().ok_or(Error::Binding)?;
        material.refund_signer_v18 = Some(
            dom_actuator::participant_retained_vault_signer_v12(
                vault,
                std::rc::Rc::clone(&owner.store),
                binding,
                chain,
                share,
            )
            .map_err(|_| Error::Vault)?,
        );
    }
    let transport = owner
        .store
        .prepare_operational_signing_transport_authority(
            chain,
            owner.session_id,
            PurposeV1::Refund,
        )?;
    match prepare_next_dom_recovery_edge_with_signer_v12(
        &owner.store,
        binding,
        chain,
        material.refund_signer_v18.as_mut().ok_or(Error::Vault)?,
        accepted,
        &transport,
    )
    .map_err(|_| Error::Vault)?
    {
        ProductionDomClaimProgressV12::AwaitingPeer => Ok(Step::AwaitingPeer),
        ProductionDomClaimProgressV12::Prepared(request) => {
            owner.sign_commit_and_stage(request, expiry)?;
            Ok(Step::Staged)
        }
        ProductionDomClaimProgressV12::SigningComplete => Err(Error::Binding),
    }
}

fn replay<F: F6TransportPortV1>(
    owner: &mut ProductionContractsV1<F>,
    recovery: OutboundDsc1RecoveryV1,
    expiry: TimelockSpec,
) -> Result<Option<Step>, Error> {
    match recovery {
        OutboundDsc1RecoveryV1::None => Ok(None),
        OutboundDsc1RecoveryV1::SigningRequest(request) => {
            if !((0x0c..=0x0e).contains(&request.message_type()) || request.message_type() == 0x10)
                || request.sender_id() != &owner.local_participant
            {
                return Err(Error::Binding);
            }
            owner.sign_commit_and_stage(*request, expiry)?;
            Ok(Some(Step::Staged))
        }
        OutboundDsc1RecoveryV1::Committed(record) => {
            let kind = SignedMessageV1::decode_exact(record.signed_bytes())
                .map_err(|_| Error::Binding)?
                .unsigned()
                .kind() as u8;
            if !((0x0c..=0x0e).contains(&kind) || kind == 0x10)
                || record.sender_id() != &owner.local_participant
            {
                return Err(Error::Binding);
            }
            owner
                .relay
                .try_borrow_mut()
                .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                .stage_store_outbound_dsc1(*record, expiry)
                .map_err(ProductionContractsOutboundErrorV1::Relay)?;
            Ok(Some(Step::Staged))
        }
    }
}
