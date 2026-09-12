//! Native Contracts origin for the independently authenticated XMR output D.
//! This provisions no files and sends nothing. The caller owns the durable
//! creation boundary; retained mode never creates a missing session.
use super::*;
use crate::production_dom_shared_bootstrap_v12::{
    ProductionBoundDomSharedOutputV12, ProductionXmrCancelledBootstrapScopeV22,
};

pub(crate) struct CancelledContractsRequestV22<'a> {
    pub(crate) parent: dom_actuator::DomSessionBindingV1,
    pub(crate) parent_leg: &'a AuthenticatedContractsLegV1,
    pub(crate) chain: TrustedChainIdV1,
    pub(crate) roster: crate::production_inputs::ProductionRosterLegV1,
    pub(crate) policy: &'a xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
    pub(crate) material: &'a ProductionBoundDomSharedOutputV12,
    pub(crate) identity: &'a ContractsTransportIdentityStoreV1,
}

pub(crate) fn initialize(
    store: &ContractsSessionStoreV1,
    request: CancelledContractsRequestV22<'_>,
    allow_create: bool,
) -> Result<PreparedEarlyTransportAuthorityV1, ProductionContractsSessionBootstrapErrorV1> {
    use ProductionContractsSessionBootstrapErrorV1 as Error;
    let CancelledContractsRequestV22 {
        parent,
        parent_leg,
        chain,
        roster,
        policy,
        material,
        identity,
    } = request;
    if parent_leg.session_id() != &parent.session_id()
        || parent_leg.terms_hash() != &parent.terms_digest()
        || parent_leg.position() != roster.position
        || chain.as_bytes() != &parent.chain_id()
    {
        return Err(Error::BootstrapRefused);
    }
    let binding = ProductionXmrCancelledBootstrapScopeV22::new(parent, roster, policy)
        .map_err(|_| Error::BootstrapRefused)?
        .binding();
    // Includes exact D session, capsule, role and policy-derived value checks.
    let _driver = crate::production_contracts::ProductionBootstrapLegV16::for_xmr_cancelled_v22(
        parent, chain, roster, policy, material,
    )
    .map_err(|_| Error::BootstrapRefused)?;
    require_local_identity_reference(
        identity,
        parent.participant().participant_id(),
        parent_leg.participants(),
    )?;
    let shared = material.shared_bindings_v22().clone();
    let mut participants = Vec::with_capacity(2);
    for (index, participant) in parent_leg.participants().iter().enumerate() {
        if participant.participant_id().0 != roster.members[index].participant_id.0
            || participant.direction() != shared[index].role()
        {
            return Err(Error::BootstrapRefused);
        }
        let derived = ParticipantIdentityV1::new(
            &chain,
            PublicKey::from_compressed_bytes(participant.schnorr_public_key())
                .map_err(|_| Error::BootstrapRefused)?,
            shared[index].share_point().clone(),
            participant.direction(),
        )
        .map_err(|_| Error::BootstrapRefused)?;
        if derived.participant_id() != shared[index].participant_id() {
            return Err(Error::BootstrapRefused);
        }
        participants.push(derived);
    }
    let participants =
        ParticipantRosterV1::new(participants).map_err(|_| Error::BootstrapRefused)?;
    let initial = SessionRecordV1::new(
        SessionRecordFieldsV1 {
            session_id: binding.session_id(),
            revision: 0,
            phase: SessionPhaseV1::Created,
            terms_hash: binding.terms_digest(),
            transcript_hash: initial_transcript_hash_v1(
                &chain,
                &binding.session_id(),
                dom_adaptor::ContractKindV1::WitnessOrTimeout,
                &participants,
            ),
            irreversible: SessionIrreversibleV1 {
                any_signing_share_sent: false,
                funding_authorized: false,
                adaptor_secret_exposed: false,
                nonce_epoch: 0,
            },
            chain: SessionChainProjectionV1 {
                tip_id: binding.genesis_hash(),
                tip_height: 0,
                funding: SessionTxObservationV1::Unknown,
                claim: SessionTxObservationV1::Unknown,
                refund: SessionTxObservationV1::Unknown,
            },
        },
        &[],
    )
    .map_err(|_| Error::BootstrapRefused)?;
    let initiator = participant_for_direction(parent_leg, DirectionV1::Initiator)?;
    let responder = participant_for_direction(parent_leg, DirectionV1::Responder)?;
    let prepared = PreparedLegBootstrapV1 {
        initial,
        transport_roster: [
            transport_participant(initiator)?,
            transport_participant(responder)?,
        ],
        identity_references: [
            transport_identity_reference(initiator)?,
            transport_identity_reference(responder)?,
        ],
        local_key_reference: *identity.reference().key_reference(),
        shared_blinding_bindings: shared,
    };
    if !allow_create {
        store
            .authenticate_bootstrap_origin_v12(&prepared.initial)
            .map_err(|_| Error::StoreRefused)?;
    }
    converge_leg_prefix(store, &prepared)?;
    reauthenticate_and_prepare_early(store, chain, &prepared)
}
