//! Public DOM principal authority for native XMR, not a wallet opening or F7 grant.
//!
//! Only the opaque Noise/local-journal provenance token can construct an owner.
//! Public offer bytes alone prove knowledge, not the identity of their sender.
//! Local, peer and authenticated restart paths commit the SAME public record;
//! neither a local wallet revision nor a transport arrival time enters it.
use super::{
    digest, direction_tag, scoped_deadline, AdapterAuthenticatedRefundFaceV2, AdapterFaceLegV2,
    ProductionF6ErrorV2 as Error, ProductionSolverF6BindingV2, EVIDENCE_DOMAIN,
    PAYOUT_COMMITMENT_DOMAIN, ZERO_DIGEST,
};
use crate::production_noise_relay::ProductionAuthenticatedXmrClaimPrincipalV25;
use deployment_registry::{AssetRepresentationV1, ResolvedDomDeploymentV1};
use dom_adaptor::{DirectionV1, TrustedChainIdV1};
use kaystra_core::{types::LockMechanism, SettlementTermsV1};
use rfq::{v2::SettlementPositionV2, LegDirectionV1};
use route_composer::ComposedBindingV2;
use xmr_refund_policy::{
    compensation::ValidatedXmrCompensationPolicyV11,
    payout_offer_v22::{XmrGraphPayoutKindV22, XmrPolicyPayoutOfferV22},
};

const DOMAIN: &[u8] = b"DOM-INTEROP/F6/ADAPTER-REFUND-FACE/DOM-XMR/V25\0";
const PRINCIPAL_DOMAIN: &[u8] = b"DOM-INTEROP/F6/DOM-XMR/VERIFIED-PRINCIPAL/V25\0";
type Result<T> = core::result::Result<T, Error>;

/// Move-only F6 terms owner. There is no raw-byte constructor, decoder,
/// public field, Clone or conversion into a private wallet payout capability.
pub(crate) struct ProductionNativeXmrDomFaceOwnerV25 {
    principal: ProductionAuthenticatedXmrClaimPrincipalV25,
}

impl ProductionNativeXmrDomFaceOwnerV25 {
    pub(crate) fn from_authenticated_principal_v25(
        principal: ProductionAuthenticatedXmrClaimPrincipalV25,
    ) -> Result<Self> {
        verify_principal(&PrincipalInputsV25::from_token(&principal))?;
        Ok(Self { principal })
    }

    /// RFQ-late adapter construction. This retains all original DOM deployment
    /// and composition checks, but never relabels a derived XMR payout as C0.
    pub(crate) fn into_face(
        self,
        binding: &ProductionSolverF6BindingV2,
        settlement: &SettlementTermsV1,
        composition: &ComposedBindingV2,
        deployment: ResolvedDomDeploymentV1,
    ) -> Result<AdapterAuthenticatedRefundFaceV2> {
        binding.validate()?;
        let principal = PrincipalInputsV25::from_token(&self.principal);
        let principal_record = verify_principal(&principal)?;
        let selected = match binding.position {
            SettlementPositionV2::Upstream => composition.upstream(),
            SettlementPositionV2::Downstream => composition.downstream(),
        };
        let terms_hash = settlement.terms_hash().map_err(|_| Error::InvalidTerms)?;
        let dom = deployment.deployment();
        let settlement_profile =
            route_time_anchor::resolved_dom_deployment_profile_digest_v25(deployment)
                .map_err(|_| Error::InvalidTerms)?;
        let asset = deployment.native_asset_binding();
        if selected != settlement
            || principal.terms != settlement
            || principal.route_id != binding.wire.route_id
            || binding.wire.session_id != settlement.session_id.0
            || binding.wire.policy_version != settlement.policy_version
            || binding.dom_chain_id != settlement.dom_leg.chain_id
            || binding.composition_id != composition.binding_digest()
            || binding.pins.registry_digest != deployment.registry_digest()
            || binding.pins.registry_epoch != deployment.registry_epoch()
            || [
                composition.binding_digest(),
                composition.route_scope_digest(),
                composition.time_policy_digest(),
                composition.time_evidence_digest(),
                composition.time_proof_digest(),
                deployment.registry_digest(),
                deployment.native_asset_binding_digest(),
            ]
            .contains(&ZERO_DIGEST)
            || composition.evidence_sequence() == 0
            || deployment.registry_epoch() == 0
            || dom.chain_id != settlement.dom_leg.chain_id
            || dom.native_asset != settlement.dom_leg.asset_id
            || settlement_profile != settlement.dom_leg.adapter_profile_hash
            || dom.finality != settlement.dom_leg.finality
            || asset.chain_id != settlement.dom_leg.chain_id
            || asset.asset_id != settlement.dom_leg.asset_id
            || !matches!(asset.representation, AssetRepresentationV1::Native)
        {
            return Err(Error::InvalidTerms);
        }
        // Resolve identity from the authenticated deployment, not a packet's
        // chain label. This is the same native derivation used by the runtime.
        let chain = TrustedChainIdV1::from_authenticated_genesis(
            dom.runtime_identity.network_magic,
            &dom_core::Hash256::from_bytes(dom.genesis_hash),
        );
        if chain.as_bytes() != principal.chain.as_bytes() {
            return Err(Error::InvalidTerms);
        }
        let deadline = scoped_deadline(settlement.dom_leg.chain_id, settlement.dom_leg.deadline)?;
        if deadline.kind != rfq::v2::NativeClockKindV2::BlockHeight {
            return Err(Error::InvalidTerms);
        }
        let direction = match binding.position {
            SettlementPositionV2::Upstream => LegDirectionV1::UserReceives,
            SettlementPositionV2::Downstream => LegDirectionV1::UserGives,
        };
        let mut record = Vec::from(DOMAIN);
        record.push(match binding.position {
            SettlementPositionV2::Upstream => 1,
            SettlementPositionV2::Downstream => 2,
        });
        record.push(direction_tag(direction));
        for field in [
            binding.wire.network_id,
            binding.wire.roster_snapshot,
            binding.wire.route_id,
            composition.binding_digest(),
            composition.route_scope_digest(),
            composition.time_policy_digest(),
            composition.time_evidence_digest(),
            composition.time_proof_digest(),
            settlement.settlement_id.0,
            settlement.session_id.0,
            terms_hash,
            settlement.dom_leg.chain_id.0,
            settlement.dom_leg.asset_id.0,
            settlement.dom_leg.adapter_profile_hash,
            deployment.registry_digest(),
            deployment.native_asset_binding_digest(),
            dom.genesis_hash,
            dom.consensus_rules_digest,
        ] {
            record.extend_from_slice(&field);
        }
        for value in [
            composition.evidence_sequence(),
            deployment.registry_epoch(),
            deadline.value,
        ] {
            record.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            binding.wire.policy_version,
            dom.runtime_identity.network_magic,
            dom.runtime_identity.protocol_version,
            dom.scriptless_api_version,
            dom.timing.min_block_seconds,
            dom.timing.max_block_seconds,
            dom.timing.max_reorg_seconds,
            dom.timing.observation_seconds,
            dom.timing.broadcast_seconds,
            dom.finality.min_confirmations,
            dom.finality.max_reorg_depth,
        ] {
            record.extend_from_slice(&value.to_be_bytes());
        }
        record.push(dom.runtime_identity.range_proof_serialization_version);
        record.push(dom.runtime_identity.network as u8);
        record.push(asset.decimals);
        append_field(&mut record, &principal_record)?;
        let payout_commitment = digest(PAYOUT_COMMITMENT_DOMAIN, &[DOMAIN, &record])?;
        // Registry epoch is a real common authenticated revision. It is NOT
        // a fabricated wallet/journal revision or renewed availability grant.
        let revision = deployment.registry_epoch();
        let evidence_digest = digest(
            EVIDENCE_DOMAIN,
            &[DOMAIN, &record, &payout_commitment, &revision.to_be_bytes()],
        )?;
        Ok(AdapterAuthenticatedRefundFaceV2 {
            leg: AdapterFaceLegV2::Dom,
            position: binding.position,
            settlement_id: settlement.settlement_id.0,
            session_id: settlement.session_id.0,
            terms_hash,
            face: rfq::v2::RefundFaceV2 {
                direction,
                chain_id: settlement.dom_leg.chain_id,
                refund_deadline: deadline,
                payout_commitment,
            },
            evidence_digest,
            evidence_revision: revision,
        })
    }
}

// Private, public-mathematics-only view. It cannot mint the outer owner: that
// constructor still requires the opaque, authenticated provenance token.
struct PrincipalInputsV25<'a> {
    terms: &'a SettlementTermsV1,
    policy: &'a ValidatedXmrCompensationPolicyV11,
    chain: &'a TrustedChainIdV1,
    route_id: [u8; 32],
    beneficiary: [u8; 32],
    participant_index: u16,
    direction: DirectionV1,
    offer: &'a XmrPolicyPayoutOfferV22,
}

impl<'a> PrincipalInputsV25<'a> {
    fn from_token(token: &'a ProductionAuthenticatedXmrClaimPrincipalV25) -> Self {
        Self {
            terms: token.terms(),
            policy: token.policy(),
            chain: token.chain(),
            route_id: token.route_id(),
            beneficiary: token.beneficiary(),
            participant_index: token.participant_index(),
            direction: token.direction(),
            offer: token.offer(),
        }
    }
}

fn verify_principal(input: &PrincipalInputsV25<'_>) -> Result<Vec<u8>> {
    let PrincipalInputsV25 {
        terms,
        policy,
        chain,
        offer,
        ..
    } = input;
    terms.validate().map_err(|_| Error::InvalidTerms)?;
    let validated = policy
        .policy()
        .validate_for(terms)
        .map_err(|_| Error::InvalidTerms)?;
    let beneficiary = terms.dom_leg.beneficiary.0;
    if &validated != *policy
        || input.route_id == ZERO_DIGEST
        || terms.dom_leg.mechanism != LockMechanism::DomAdaptor2of2
        || terms.counterparty_leg.mechanism != LockMechanism::CrossCurveSharedSpend
        || input.beneficiary != beneficiary
        || beneficiary != policy.policy().xmr_funder
        || terms
            .roster
            .get(usize::from(input.participant_index))
            .map(|id| id.0)
            != Some(beneficiary)
        || chain.as_bytes() != &terms.dom_leg.chain_id.0
        || offer.kind() != XmrGraphPayoutKindV22::ClaimPrincipal
        || u128::from(policy.policy().dom_principal_noms) != terms.dom_leg.amount
        || offer.output().commitment.as_bytes() != &policy.policy().claim_principal_commitment
        || offer
            .output()
            .recovery_capsule()
            .map_err(|_| Error::InvalidTerms)?
            .is_some()
    {
        return Err(Error::InvalidTerms);
    }
    offer
        .verify(terms, policy, chain, input.direction)
        .map_err(|_| Error::InvalidTerms)?;
    let ownership = offer.ownership().ok_or(Error::InvalidTerms)?;
    if ownership.statement.participant_index() != input.participant_index
        || ownership.statement.participant_id() != beneficiary
        || ownership.statement.role() != input.direction
    {
        return Err(Error::InvalidTerms);
    }
    ownership
        .statement
        .require_authenticated_roster_v22(&terms.roster.map(|id| id.0))
        .map_err(|_| Error::InvalidTerms)?;
    let bytes = offer.to_bytes().map_err(|_| Error::InvalidTerms)?;
    let decoded =
        XmrPolicyPayoutOfferV22::from_bytes(&bytes, terms, policy, chain, input.direction)
            .map_err(|_| Error::InvalidTerms)?;
    if decoded.to_bytes().map_err(|_| Error::InvalidTerms)? != bytes {
        return Err(Error::InvalidTerms);
    }
    let mut record = Vec::from(PRINCIPAL_DOMAIN);
    for field in [
        input.route_id,
        *chain.as_bytes(),
        terms.session_id.0,
        *policy.terms_hash(),
        beneficiary,
    ] {
        record.extend_from_slice(&field);
    }
    for participant in terms.roster {
        record.extend_from_slice(&participant.0);
    }
    record.extend_from_slice(&input.participant_index.to_be_bytes());
    record.push(input.direction.to_byte());
    append_field(
        &mut record,
        &policy
            .policy()
            .to_bytes()
            .map_err(|_| Error::InvalidTerms)?,
    )?;
    append_field(&mut record, &bytes)?;
    Ok(record)
}

fn append_field(record: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| Error::InvalidTerms)?;
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
#[path = "native_xmr_dom_face_v25_tests.rs"]
mod tests;
