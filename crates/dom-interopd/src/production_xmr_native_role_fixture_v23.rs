//! Component role binding from two real settlements and canonical native Claim
//! templates. These fixture domains are not daemon composition/F6 admission.
use crate::production_noise_relay::SignedNativeGraphFixtureV23;
use dom_adaptor::{AcceptedSigningSessionV1, ParticipantIdentityV1, ParticipantRosterV1};
use dom_final_claim_binding::*;
use kaystra_core::terms::SettlementTermsV1;
use xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningStageV22 as Stage;

pub(super) fn roles(
    signed: &SignedNativeGraphFixtureV23,
    terms: &[SettlementTermsV1; 2],
    downstream_claim: [u8; 32],
) -> Result<[FinalClaimRoleBindingV1; 2], Box<dyn std::error::Error>> {
    let route = signed.wallets[0].0.route_id();
    let claims = [signed.keys[0].template_hash(Stage::Claim), downstream_claim];
    if claims[0] == claims[1]
        || downstream_claim == [0; 32]
        || terms[0].session_id == terms[1].session_id
        || terms[0].adaptor_point_sec1 != terms[1].adaptor_point_sec1
    {
        return Err("native fixture composed scope mismatch".into());
    }
    let mut public = route.to_vec();
    for (terms, claim) in terms.iter().zip(claims) {
        let bytes = terms.canonical_bytes()?;
        public.extend_from_slice(&u32::try_from(bytes.len())?.to_le_bytes());
        public.extend_from_slice(&bytes);
        public.extend_from_slice(&claim);
    }
    let composition =
        *dom_crypto::blake2b_256_tagged("DOM/NativeXmrComponentFixture/Composition/V23", &public)
            .as_bytes();
    let route_scope =
        *dom_crypto::blake2b_256_tagged("DOM/NativeXmrComponentFixture/RouteScope/V23", &public)
            .as_bytes();
    let mut scopes = Vec::new();
    let mut selections = Vec::new();
    for (terms, claim) in terms.iter().zip(claims) {
        // The authenticated native T owner is the XMR funder on both legs.
        let sender = terms.counterparty_leg.refund_to;
        let scope = FinalClaimSecretSourceScopeV1::new(FinalClaimSecretSourceScopeInputV1 {
            secret_source: FinalClaimSecretSourceV1::LocalOrigin,
            reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
            route_id: route,
            composition_binding_digest: composition,
            source_chain_id: terms.dom_leg.chain_id,
            source_settlement_id: terms.settlement_id,
            source_session_id: terms.session_id,
            source_claim_template_hash: claim,
            adaptor_point_sec1: terms.adaptor_point_sec1,
            adaptor_secret_origin_id: sender,
            dom_claim_sender_id: sender,
        })?;
        selections.push(FinalClaimRoleSelectionV1::new(
            sender,
            sender,
            terms.dom_leg.refund_to,
            FinalClaimRevealModeV1::DomRevealsFirst,
            FinalClaimSecretSourceV1::LocalOrigin,
            scope.clone(),
        )?);
        scopes.push(scope);
    }
    let [upstream_selection, downstream_selection]: [_; 2] = selections
        .try_into()
        .map_err(|_| "two explicit native selections required")?;
    let plan = ComposedFinalClaimRolePlanV1::bind(ComposedFinalClaimRolePlanInputV1 {
        route_id: route,
        route_scope_digest: route_scope,
        composition_binding_digest: composition,
        upstream_terms: &terms[0],
        downstream_terms: &terms[1],
        upstream_selection,
        downstream_selection,
    })?;
    let mut roles = Vec::new();
    for actor in 0..2 {
        let keys = &signed.keys[actor];
        keys.require_route(route)?;
        let accepted = signed.stores[actor].resume_xmr_graph_signing_session_v23(
            terms[0].session_id.0,
            dom_scriptless_store::XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
        )?;
        let entries = accepted.roster().entries();
        if entries.len() != 2 {
            return Err("native U roster cardinality".into());
        }
        keys.require_scope(
            &signed.chain,
            terms[0].session_id.0,
            terms[0].terms_hash()?,
            [*entries[0].participant_id(), *entries[1].participant_id()],
            [entries[0].direction(), entries[1].direction()],
        )?;
        let roster = ParticipantRosterV1::new(
            entries
                .iter()
                .map(|identity| {
                    Ok(ParticipantIdentityV1::new(
                        &signed.chain,
                        identity.identity_public_key().clone(),
                        keys.key(Stage::Claim, *identity.participant_id(), claims[0])?
                            .clone(),
                        identity.direction(),
                    )?)
                })
                .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?,
        )?;
        let graph = signed.produced[actor].graph();
        if graph.binding().terms_hash != terms[0].terms_hash()? {
            return Err("native produced terms mismatch".into());
        }
        roles.push(FinalClaimRoleBindingV1::bind(
            &signed.chain,
            FinalClaimRoleBindingInputV1 {
                terms: &terms[0],
                roster: &roster,
                role_plan: &plan,
                source_scope: &scopes[0],
                route_leg: ComposedSettlementLegV1::Upstream,
                funding_template_hash: keys.template_hash(Stage::Funding),
                claim_template_hash: claims[0],
                refund_template_hash: keys.template_hash(Stage::Refund),
                shared_output_commitment: graph.binding().funding_commitment,
                claim_kernel_index: 0,
            },
        )?);
    }
    if roles[0].canonical_bytes()? != roles[1].canonical_bytes()? {
        return Err("native peers disagree on component role".into());
    }
    roles
        .try_into()
        .map_err(|_| "two native roles required".into())
}
