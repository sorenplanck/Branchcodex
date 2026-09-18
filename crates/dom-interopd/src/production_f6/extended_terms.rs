//! F6 payout commitments for authenticated SOL/XMR sessions.
//!
//! These owners commit terms; they do not prove live funding or executor
//! readiness. Stage 13 must independently arm refunds before any funding.
#[path = "xmr_enrollment_terms_v23.rs"]
mod xmr_enrollment_terms_v23;

use super::terms::{
    digest, direction_tag, scoped_deadline, AdapterAuthenticatedRefundFaceV2, AdapterFaceLegV2,
    EVIDENCE_DOMAIN, PAYOUT_COMMITMENT_DOMAIN,
};
use super::{ProductionF6ErrorV2, ProductionSolverF6BindingV2};
use crate::production_inputs::{
    AuthenticatedSolanaSessionBindingsV1, AuthenticatedXmrSessionBindingsV1,
};
use crate::ProductionRoutePositionV1;
use deployment_registry::{ResolvedMoneroDeploymentV1, ResolvedSolanaDeploymentV1};
use kaystra_core::{
    terms::SettlementTermsV1,
    types::{LockMechanism, TimelockSpec},
};
use rfq::{v2::SettlementPositionV2, LegDirectionV1};
use route_composer::ComposedBindingV2;
use solana_profile::{SolanaAdapterProfileV1, ValidatedSolanaSetup};
use xmr_setup_profile::{ValidatedXmrSetup, XmrAdapterProfileV1, XmrProofContextV1};

const DOMAIN_SOL: &[u8] = b"DOM-INTEROP/F6/ADAPTER-REFUND-FACE/SOL/V7\0";
const DOMAIN_XMR: &[u8] = b"DOM-INTEROP/F6/ADAPTER-REFUND-FACE/XMR/V7\0";
const DOMAIN_XMR_ENROLLMENT: &[u8] = b"DOM-INTEROP/F6/ADAPTER-REFUND-FACE/XMR-ENROLLMENT/V23\0";

#[derive(Clone)]
enum XmrRefundTermsV23 {
    Legacy(crate::production_inputs::ProductionXmrRefundBundleV1),
    Enrollment(crate::production_inputs::ProductionXmrEnrollmentBundleV23),
}

struct SessionScope {
    position: SettlementPositionV2,
    route_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
}

fn position(value: ProductionRoutePositionV1) -> SettlementPositionV2 {
    match value {
        ProductionRoutePositionV1::Upstream => SettlementPositionV2::Upstream,
        ProductionRoutePositionV1::Downstream => SettlementPositionV2::Downstream,
    }
}

/// No caller-shaped payout or digest constructor: session authentication is
/// the only way to acquire this owner. It can be consumed by F6 exactly once.
pub(crate) struct ProductionSolanaF6TermsOwnerV7 {
    scope: SessionScope,
    setup: ValidatedSolanaSetup,
    profile: SolanaAdapterProfileV1,
    deployment: ResolvedSolanaDeploymentV1,
    account_binding: Option<crate::production_inputs::ProductionSolanaAccountBindingV25>,
}

pub(crate) struct ProductionXmrF6TermsOwnerV7 {
    scope: SessionScope,
    setup: ValidatedXmrSetup,
    profile: XmrAdapterProfileV1,
    deployment: ResolvedMoneroDeploymentV1,
    refund: XmrRefundTermsV23,
}

impl SessionScope {
    fn check(
        &self,
        binding: &ProductionSolverF6BindingV2,
        terms: &SettlementTermsV1,
        composition: &ComposedBindingV2,
        registry: [u8; 32],
        epoch: u64,
    ) -> Result<Vec<u8>, ProductionF6ErrorV2> {
        binding.validate()?;
        terms
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let selected = match self.position {
            SettlementPositionV2::Upstream => composition.upstream(),
            SettlementPositionV2::Downstream => composition.downstream(),
        };
        if self.position != binding.position
            || self.route_id != binding.wire.route_id
            || self.session_id != binding.wire.session_id
            || self.session_id != terms.session_id.0
            || self.terms_hash
                != terms
                    .terms_hash()
                    .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?
            || selected != terms
            || composition.binding_digest() != binding.composition_id
            || binding.dom_chain_id != terms.dom_leg.chain_id
            || binding.pins.registry_digest != registry
            || binding.pins.registry_epoch != epoch
            || epoch == 0
            || [
                self.route_id,
                self.session_id,
                self.terms_hash,
                registry,
                composition.binding_digest(),
                composition.route_scope_digest(),
            ]
            .contains(&[0; 32])
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        let mut record = Vec::new();
        record.push(match self.position {
            SettlementPositionV2::Upstream => 1,
            SettlementPositionV2::Downstream => 2,
        });
        record.push(direction_tag(self.direction()));
        for field in [
            self.route_id,
            self.session_id,
            self.terms_hash,
            terms.settlement_id.0,
            composition.binding_digest(),
            composition.route_scope_digest(),
            registry,
            terms.counterparty_leg.chain_id.0,
            terms.counterparty_leg.asset_id.0,
            terms.counterparty_leg.adapter_profile_hash,
        ] {
            record.extend_from_slice(&field);
        }
        record.extend_from_slice(&epoch.to_be_bytes());
        record.extend_from_slice(&terms.counterparty_leg.amount.to_be_bytes());
        record.extend_from_slice(&terms.fee_limit.counterparty_max.to_be_bytes());
        record.extend_from_slice(
            &scoped_deadline(
                terms.counterparty_leg.chain_id,
                terms.counterparty_leg.deadline,
            )?
            .value
            .to_be_bytes(),
        );
        Ok(record)
    }

    fn direction(&self) -> LegDirectionV1 {
        match self.position {
            SettlementPositionV2::Upstream => LegDirectionV1::UserGives,
            SettlementPositionV2::Downstream => LegDirectionV1::UserReceives,
        }
    }

    fn finish(
        self,
        terms: &SettlementTermsV1,
        domain: &[u8],
        record: &[u8],
        epoch: u64,
    ) -> Result<AdapterAuthenticatedRefundFaceV2, ProductionF6ErrorV2> {
        let payout_commitment = digest(PAYOUT_COMMITMENT_DOMAIN, &[domain, record])?;
        let evidence_digest = digest(EVIDENCE_DOMAIN, &[domain, record, &payout_commitment])?;
        Ok(AdapterAuthenticatedRefundFaceV2 {
            leg: AdapterFaceLegV2::Counterparty,
            position: self.position,
            settlement_id: terms.settlement_id.0,
            session_id: self.session_id,
            terms_hash: self.terms_hash,
            face: rfq::v2::RefundFaceV2 {
                direction: self.direction(),
                chain_id: terms.counterparty_leg.chain_id,
                refund_deadline: scoped_deadline(
                    terms.counterparty_leg.chain_id,
                    terms.counterparty_leg.deadline,
                )?,
                payout_commitment,
            },
            evidence_digest,
            evidence_revision: epoch,
        })
    }
}

impl ProductionSolanaF6TermsOwnerV7 {
    pub(crate) fn from_session(session: &AuthenticatedSolanaSessionBindingsV1) -> Self {
        Self {
            scope: SessionScope {
                position: position(session.position()),
                route_id: session.route_id(),
                session_id: session.session_id(),
                terms_hash: session.terms_digest(),
            },
            setup: session.setup().clone(),
            profile: *session.profile(),
            deployment: session.deployment().clone(),
            account_binding: session.account_binding_v25().copied(),
        }
    }

    pub(crate) fn into_face(
        self,
        binding: &ProductionSolverF6BindingV2,
        terms: &SettlementTermsV1,
        composition: &ComposedBindingV2,
    ) -> Result<AdapterAuthenticatedRefundFaceV2, ProductionF6ErrorV2> {
        if !matches!(terms.counterparty_leg.deadline, TimelockSpec::TimestampSeconds { value } if value > 0)
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        let epoch = self.deployment.registry_epoch();
        let mut record = self.scope.check(
            binding,
            terms,
            composition,
            self.deployment.registry_digest(),
            epoch,
        )?;
        let setup = &self.setup;
        // The adapter profile hash and registry chain-profile digest are distinct
        // domains. Compare each to its corresponding authenticated object.
        // A frozen V1 setup pins the operational hash and pays the participant
        // identities; a V25 setup pins the registry digest and pays the
        // accounts its dual-signed proofs authenticated.
        let (expected_hash, accounts_match) = match &self.account_binding {
            None => (
                self.profile.profile_hash(),
                setup.recipient().0 == terms.counterparty_leg.beneficiary.0
                    && setup.refund_recipient().0 == terms.counterparty_leg.refund_to.0,
            ),
            Some(binding) => (
                self.deployment.profile_digest(),
                setup.funder() == binding.funder()
                    && setup.recipient() == binding.recipient()
                    && setup.refund_recipient() == binding.refund_recipient()
                    && setup.funder() == setup.refund_recipient()
                    && binding.funder() == binding.refund_recipient()
                    && setup.funder() != setup.recipient(),
            ),
        };
        if expected_hash != terms.counterparty_leg.adapter_profile_hash
            || self.deployment.profile().chain_id != terms.counterparty_leg.chain_id
            || self.deployment.asset_binding().asset_id != terms.counterparty_leg.asset_id
            || terms.counterparty_leg.mechanism != LockMechanism::CrossCurveConditionLock
            || setup.settlement_id() != terms.settlement_id.0
            || setup.terms_hash() != self.scope.terms_hash
            || u128::from(setup.amount()) != terms.counterparty_leg.amount
            || !accounts_match
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        let (program, code) = match self.deployment.profile().kind {
            chain_profile::ChainKindV1::Solana {
                escrow_program,
                program_data_hash,
                ..
            } => (escrow_program, program_data_hash),
            _ => return Err(ProductionF6ErrorV2::InvalidTerms),
        };
        if program != setup.program_id().0 || code != setup.program_data_hash() {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        for field in [
            self.deployment.profile_digest(),
            self.deployment.asset_binding_digest(),
            self.deployment.deployment().genesis_hash,
            setup.binding_hash(),
            setup.setup_id(),
            setup.program_id().0,
            setup.state_pda().0,
            setup.vault_pda().0,
            setup.vault_authority().0,
            setup.funder().0,
            setup.recipient().0,
            setup.refund_recipient().0,
            setup.asset().mint().0,
            setup.asset().token_program().0,
            setup.program_data_hash(),
            setup.claim().ed_compressed,
        ] {
            record.extend_from_slice(&field);
        }
        // Both daemons derive the same V25 proof digests from the same
        // authenticated bundle; a V1 record keeps its exact earlier bytes.
        if let Some(binding) = &self.account_binding {
            record.extend_from_slice(&binding.funder_binding_digest());
            record.extend_from_slice(&binding.beneficiary_binding_digest());
        }
        record.extend_from_slice(&setup.claim().secp_compressed);
        record.push(setup.asset().decimals());
        record.extend_from_slice(&self.deployment.deployment().max_fee_lamports.to_be_bytes());
        self.scope.finish(terms, DOMAIN_SOL, &record, epoch)
    }
}

impl ProductionXmrF6TermsOwnerV7 {
    pub(crate) fn from_session(
        session: &AuthenticatedXmrSessionBindingsV1,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Ok(Self {
            scope: SessionScope {
                position: position(session.position()),
                route_id: session.route_id(),
                session_id: session.session_id(),
                terms_hash: session.terms_digest(),
            },
            setup: session.setup().clone(),
            profile: *session.profile(),
            deployment: session.deployment().clone(),
            refund: match (
                session.refund_bundle(),
                session.native_enrollment_bundle_v23(),
                session.native_enrollment_v23(),
            ) {
                (Some(refund), None, None) => XmrRefundTermsV23::Legacy(refund.clone()),
                (None, Some(enrollment), Some(prepared)) => {
                    prepared
                        .require_setup(session.setup(), enrollment.proof())
                        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
                    XmrRefundTermsV23::Enrollment(enrollment.clone())
                }
                _ => return Err(ProductionF6ErrorV2::InvalidTerms),
            },
        })
    }

    pub(crate) fn into_face(
        self,
        binding: &ProductionSolverF6BindingV2,
        terms: &SettlementTermsV1,
        composition: &ComposedBindingV2,
    ) -> Result<AdapterAuthenticatedRefundFaceV2, ProductionF6ErrorV2> {
        let refund = match self.refund.clone() {
            XmrRefundTermsV23::Legacy(refund) => refund,
            XmrRefundTermsV23::Enrollment(enrollment) => {
                return self.into_enrollment_face_v23(binding, terms, composition, enrollment);
            }
        };
        xmr_setup_profile::require_setup_chain_profile_v24(
            terms,
            &self.profile,
            &self.setup,
            self.deployment.profile(),
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        if !matches!(terms.counterparty_leg.deadline, TimelockSpec::TimestampSeconds { value } if value > 0)
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        let epoch = self.deployment.registry_epoch();
        let mut record = self.scope.check(
            binding,
            terms,
            composition,
            self.deployment.registry_digest(),
            epoch,
        )?;
        if self.deployment.profile_digest() != terms.counterparty_leg.adapter_profile_hash
            || self.deployment.profile().chain_id != terms.counterparty_leg.chain_id
            || self.deployment.asset_binding().asset_id != terms.counterparty_leg.asset_id
            || !matches!(
                self.deployment.profile().kind,
                chain_profile::ChainKindV1::Monero { .. }
            )
            || terms.counterparty_leg.mechanism != LockMechanism::CrossCurveSharedSpend
            || self.setup.settlement_id() != terms.settlement_id.0
            || self.setup.terms_hash() != self.scope.terms_hash
            || refund.deadline
                != scoped_deadline(
                    terms.counterparty_leg.chain_id,
                    terms.counterparty_leg.deadline,
                )?
                .value
            || refund.template_hash == [0; 32]
            || refund.executor_profile_hash == [0; 32]
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        let context = XmrProofContextV1 {
            settlement_id: terms.settlement_id.0,
            chain_id: terms.counterparty_leg.chain_id.0,
            asset_id: terms.counterparty_leg.asset_id.0,
            amount_piconero: terms.counterparty_leg.amount,
            min_confirmations: terms.counterparty_leg.finality.min_confirmations,
            max_reorg_depth: terms.counterparty_leg.finality.max_reorg_depth,
        };
        let context_hash = xmr_setup_profile::proof_context_hash(&self.profile, &context)
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let claim = xmr_refund_adaptor::verify_refund_bundle(
            &refund.proof,
            &terms.settlement_id.0,
            &context_hash,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        if claim.secp_compressed != refund.adaptor_point_sec1 {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        for field in [
            self.deployment.profile_digest(),
            self.deployment.asset_binding_digest(),
            self.deployment.deployment().genesis_hash,
            self.setup.binding_hash(),
            self.setup.funding_tx_hash(),
            self.setup.combined_spend_public_key(),
            refund
                .proof
                .binding_hash()
                .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?,
            refund.template_hash,
            refund.executor_profile_hash,
        ] {
            record.extend_from_slice(&field);
        }
        record.extend_from_slice(&refund.adaptor_point_sec1);
        let destination = self.setup.destination().as_bytes();
        let length =
            u16::try_from(destination.len()).map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(destination);
        self.scope.finish(terms, DOMAIN_XMR, &record, epoch)
    }
}
