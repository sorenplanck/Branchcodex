//! Bilateral D share ceremony and reopen-only mounting under the parent plan.
use super::*;
use crate::production_dom_shared_bootstrap_v12::ProductionXmrCancelledBootstrapScopeV22;

fn scope(
    context: &Context,
    leg: usize,
    participant: usize,
) -> Result13<ProductionXmrCancelledBootstrapScopeV22> {
    ProductionXmrCancelledBootstrapScopeV22::new(
        context.bindings[leg][participant],
        context.rosters.legs()[leg],
        context.xmr_policies[leg]
            .as_ref()
            .ok_or(BootstrapCommandErrorV13::Binding)?,
    )
    .map_err(|_| BootstrapCommandErrorV13::Binding)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare(
    context: &Context,
    plan: &Plan,
    root: &Arc<Dir>,
    work: &Path,
    unlock: &[u8; 32],
    budget: &BudgetPolicyV1,
    relay: &[Option<Zeroizing<[u8; 32]>>; 2],
    journal: &mut Journal,
    progress: &mut BootstrapProgressV13,
) -> Result13<bool> {
    use BootstrapCommandErrorV13::{Binding, Custody, Peer};
    let mut complete = true;
    for leg in 0..2 {
        if context.xmr_policies[leg].is_none() {
            continue;
        }
        let Some(participant) = context.rosters.legs()[leg]
            .members
            .iter()
            .position(|m| m.participant_id.0 == plan.local_participant_id)
        else {
            continue;
        };
        let slot = 2 * leg + participant;
        let offer_name = packet_name("cancelled-offer", slot);
        let reveal_name = packet_name("cancelled-reveal", slot);
        let d = scope(context, leg, participant)?;
        // Once the public offer is durable, missing private material is damage.
        let allow_create = journal.get(&offer_name)?.is_none();
        let vault = provision_bootstrap_vault_v13(
            Arc::clone(root),
            d.binding(),
            unlock,
            budget.clone(),
            allow_create,
        )
        .map_err(|_| Custody)?;
        let native = open_prepared_journal(
            &work.join(format!("cancelled-{slot}.sqlite")),
            d.journal_binding().map_err(|_| Binding)?,
            allow_create,
        )?;
        let mut owner = if allow_create {
            d.open(vault, native, context.chain)
        } else {
            d.open_retained(vault, native, context.chain)
        }
        .map_err(|_| Custody)?;
        let signing_key = relay[leg].as_deref().ok_or(Custody)?;
        let offer = owner.local_commit(signing_key).map_err(|_| Custody)?;
        journal.publish(&offer_name, &offer)?;
        progress.local_packets.push(offer_name);
        let peer_offer_name = packet_name("cancelled-offer", slot ^ 1);
        let Some(peer_offer) = journal.receive(&peer_offer_name)? else {
            progress.awaiting.push(peer_offer_name);
            complete = false;
            continue;
        };
        owner.accept_peer_commit(&peer_offer).map_err(|_| Peer)?;
        journal.retain(&peer_offer_name, &peer_offer)?;
        let reveal = owner.local_reveal(signing_key).map_err(|_| Custody)?;
        journal.publish(&reveal_name, &reveal)?;
        progress.local_packets.push(reveal_name);
        let peer_reveal_name = packet_name("cancelled-reveal", slot ^ 1);
        let Some(peer_reveal) = journal.receive(&peer_reveal_name)? else {
            progress.awaiting.push(peer_reveal_name);
            complete = false;
            continue;
        };
        // Finish authenticates the peer and durably seals the capsule-bound
        // private share before the coordinator regards this phase as complete.
        let bound = owner.finish(&peer_reveal).map_err(|_| Peer)?;
        journal.retain(&peer_reveal_name, &peer_reveal)?;
        let expected = scope(context, leg, participant)?.binding();
        if bound.capability.binding().session_id() != &expected.session_id() {
            return Err(Binding);
        }
    }
    if !complete {
        progress.stage = "cancelled-shares";
    }
    Ok(complete)
}

pub(super) fn resume(
    context: &Context,
    plan: &Plan,
    root: &Arc<Dir>,
    work: &Path,
    unlock: &[u8; 32],
    budget: &BudgetPolicyV1,
) -> Result13<[Option<ProductionBoundDomSharedOutputV12>; 2]> {
    use BootstrapCommandErrorV13::{Binding, Custody};
    let mut shares = [None, None];
    for leg in 0..2 {
        if context.xmr_policies[leg].is_none() {
            continue;
        }
        let participant = context.rosters.legs()[leg]
            .members
            .iter()
            .position(|m| m.participant_id.0 == plan.local_participant_id)
            .ok_or(Binding)?;
        let slot = 2 * leg + participant;
        let d = scope(context, leg, participant)?;
        let vault = provision_bootstrap_vault_v13(
            Arc::clone(root),
            d.binding(),
            unlock,
            budget.clone(),
            false,
        )
        .map_err(|_| Custody)?;
        let native = store::Store::open_production(
            &work.join(format!("cancelled-{slot}.sqlite")),
            d.journal_binding().map_err(|_| Binding)?,
        )
        .map_err(|_| Custody)?;
        shares[leg] = Some(
            d.open_retained(vault, native, context.chain)
                .map_err(|_| Custody)?
                .finish_retained()
                .map_err(|_| Custody)?,
        );
    }
    Ok(shares)
}

/// Provision the real D Contracts origin before publishing a completed parent
/// artifact. Creation and readiness are separate immutable coordinator records.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_contracts(
    context: &Context,
    plan: &Plan,
    root: &Arc<Dir>,
    work: &Path,
    unlock: &[u8; 32],
    budget: &BudgetPolicyV1,
    identity: &ContractsTransportIdentityStoreV1,
    authenticated: &AuthenticatedContractsBootstrapV1,
    journal: &mut Journal,
) -> Result13<()> {
    use crate::production_contracts_session_bootstrap::xmr_cancelled_v22::{
        initialize, CancelledContractsRequestV22,
    };
    use dom_scriptless_store::ContractsSessionStoreV1;
    use BootstrapCommandErrorV13::{Binding, Custody, Storage};
    let shares = resume(context, plan, root, work, unlock, budget)?;
    for (leg, share) in shares.iter().enumerate() {
        let Some(material) = share.as_ref() else {
            continue;
        };
        let participant = context.rosters.legs()[leg]
            .members
            .iter()
            .position(|m| m.participant_id.0 == plan.local_participant_id)
            .ok_or(Binding)?;
        let slot = 2 * leg + participant;
        let binding = context.bindings[leg][participant];
        let creation_binding = contracts_creation_binding(context, leg, participant)?;
        let prepare = packet_name("cancelled-contracts-prepare", slot);
        let ready = packet_name("cancelled-contracts-ready", slot);
        let retained_ready = journal.get(&ready)?;
        let retained_prepare = journal.get(&prepare)?;
        if retained_ready
            .as_deref()
            .is_some_and(|b| b != creation_binding)
            || retained_prepare
                .as_deref()
                .is_some_and(|b| b != creation_binding)
            || (retained_ready.is_some() && retained_prepare.is_none())
        {
            return Err(Custody);
        }
        // A completed public artifact is never permission to replace missing
        // private Contracts state or an absent provisioning marker.
        if journal.get(ARTIFACT)?.is_some() && retained_ready.is_none() {
            return Err(Custody);
        }
        journal.retain(&prepare, &creation_binding)?;
        let name = format!("cancelled-contracts-{slot}");
        let store = if retained_ready.is_some() {
            ContractsSessionStoreV1::open_production(Arc::clone(root), &name, budget.clone())
        } else {
            ContractsSessionStoreV1::resume_create_production(
                Arc::clone(root),
                &name,
                budget.clone(),
                creation_binding,
            )
        }
        .map_err(|_| Storage)?;
        let _early = initialize(
            &store,
            CancelledContractsRequestV22 {
                parent: binding,
                parent_leg: &authenticated.legs()[leg],
                chain: context.chain,
                roster: context.rosters.legs()[leg],
                policy: context.xmr_policies[leg].as_ref().ok_or(Binding)?,
                material,
                identity,
            },
            retained_ready.is_none(),
        )
        .map_err(|_| Custody)?;
        journal.retain(&ready, &creation_binding)?;
    }
    Ok(())
}

/// Own the same physical D Contracts opening until Stage 12 consumes it.
pub(crate) struct MountedCancelledContractsV22 {
    pub(crate) work_dir: PathBuf,
    pub(crate) store: dom_scriptless_store::ContractsSessionStoreV1,
    pub(crate) early: Option<dom_scriptless_store::PreparedEarlyTransportAuthorityV1>,
    pub(crate) policy: xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
    pub(crate) roster: crate::production_inputs::ProductionRosterLegV1,
}

impl MountedCancelledContractsV22 {
    pub(crate) fn reauthenticate(
        &mut self,
        parent: DomSessionBindingV1,
        parent_leg: &AuthenticatedContractsLegV1,
        chain: TrustedChainIdV1,
        material: &ProductionBoundDomSharedOutputV12,
        identity: &ContractsTransportIdentityStoreV1,
    ) -> Result13<()> {
        use crate::production_contracts_session_bootstrap::xmr_cancelled_v22::{
            initialize, CancelledContractsRequestV22,
        };
        self.early = Some(
            initialize(
                &self.store,
                CancelledContractsRequestV22 {
                    parent,
                    parent_leg,
                    chain,
                    material,
                    identity,
                    roster: self.roster,
                    policy: &self.policy,
                },
                false,
            )
            .map_err(|_| BootstrapCommandErrorV13::Custody)?,
        );
        Ok(())
    }
}

fn contracts_creation_binding(
    context: &Context,
    leg: usize,
    participant: usize,
) -> Result13<[u8; 32]> {
    let parent = context.bindings[leg][participant];
    let d = scope(context, leg, participant)?;
    let mut bytes = bootstrap_scope(parent, &context.rosters.legs()[leg]).to_vec();
    bytes.extend_from_slice(&d.binding().session_id());
    hash(b"DOM/XMR-CANCELLED-CONTRACTS/V22\0", &bytes)
}

/// Runtime opening never prepares missing files or creates missing sessions.
/// Stage 10 reauthenticates the origin using its already-open identity owner.
pub(super) fn resume_contracts(
    context: &Context,
    plan: &Plan,
    root: &Arc<Dir>,
    budget: &BudgetPolicyV1,
    journal: &Journal,
) -> Result13<[Option<MountedCancelledContractsV22>; 2]> {
    use BootstrapCommandErrorV13::{Binding, Custody};
    let mut owners = [None, None];
    for leg in 0..2 {
        let Some(policy) = context.xmr_policies[leg].as_ref() else {
            continue;
        };
        let participant = context.rosters.legs()[leg]
            .members
            .iter()
            .position(|m| m.participant_id.0 == plan.local_participant_id)
            .ok_or(Binding)?;
        let slot = 2 * leg + participant;
        let expected = contracts_creation_binding(context, leg, participant)?;
        if journal
            .get(&packet_name("cancelled-contracts-prepare", slot))?
            .as_deref()
            != Some(expected.as_slice())
            || journal
                .get(&packet_name("cancelled-contracts-ready", slot))?
                .as_deref()
                != Some(expected.as_slice())
        {
            return Err(Custody);
        }
        let store = dom_scriptless_store::ContractsSessionStoreV1::open_production(
            Arc::clone(root),
            &format!("cancelled-contracts-{slot}"),
            budget.clone(),
        )
        .map_err(|_| Custody)?;
        let head = store
            .load_session(scope(context, leg, participant)?.binding().session_id())
            .map_err(|_| Custody)?;
        if head.terms_hash() != *policy.terms_hash() {
            return Err(Custody);
        }
        owners[leg] = Some(MountedCancelledContractsV22 {
            store,
            work_dir: journal.path.clone(),
            early: None,
            policy: policy.clone(),
            roster: context.rosters.legs()[leg],
        });
    }
    Ok(owners)
}
