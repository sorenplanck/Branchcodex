//! Concrete Bitcoin Core → F7 → retained Contracts → M.8 → claim handoff.
//! No caller callback can substitute a timing window or a Boolean for F7.
//! The driver retains its consumed Contracts owner across transport retries.
use crate::production_chain_signers::ProductionBitcoinParticipantAuthorityV1;
use crate::production_child_btc::ProductionBitcoinClaimMaterializationAuthorityV1;
use crate::production_child_btc::ProductionBitcoinFundingAuthorityV1;
use crate::production_child_dom::ProductionDomF7ScannerAuthorityV1;
use crate::production_contracts::{
    ProductionContractsConsumedPostAnchorV2, ProductionContractsPostAnchorErrorV2,
};
use crate::production_f7_m8::{select_local_f7_authorization_v8, ProductionF7M8ErrorV2};
use crate::production_inputs::AuthenticatedProductionInputsV1;
use crate::production_relay_stage12::ProductionRelayStage12OwnerV1;
use adapter_btc::timelock::M8TimingPolicyV1;
use adapter_btc_live::{BitcoinCoreEvidenceCollectorV1, BitcoinCoreRpcClientV1, LiveBitcoinError};
use btc_actuator::{
    BitcoinActuationScopeV1, BitcoinActuatorErrorV1, BitcoinClaimDriverErrorV6,
    BitcoinClaimSessionV1, BitcoinClaimTransportV6, DurableBitcoinActuatorV1,
};
use dom_final_claim_binding::{FinalClaimRoleBindingV1, OperationalM8ReadyBindingV2};
use route_composer::{ComposedFinalClaimRolePlanV1, FinalClaimSecretSourceScopeV1};
use route_executor::LegIdV1;

#[derive(Debug, thiserror::Error)]
pub(crate) enum BitcoinPostAnchorErrorV8 {
    #[error("Bitcoin claim scope rejected before signing")]
    Scope,
    #[error("Bitcoin funding observation failed")]
    Funding(#[source] LiveBitcoinError),
    #[error("fresh F7 validation failed")]
    F7(#[source] ProductionF7M8ErrorV2),
    #[error("retained post-anchor Contracts authority rejected")]
    Contracts(#[source] ProductionContractsPostAnchorErrorV2),
    #[error("Bitcoin participant exchange failed")]
    Exchange(#[source] BitcoinClaimDriverErrorV6),
    #[error("Bitcoin claim action has not been materialized yet")]
    AwaitingClaimMaterialization,
    #[error("host clock unavailable")]
    Clock,
}

/// Immutable public inputs cross-checked against both authenticated legs.
pub(crate) struct BitcoinPostAnchorRequestV8<'a> {
    pub(crate) inputs: &'a AuthenticatedProductionInputsV1,
    pub(crate) role_plan: &'a ComposedFinalClaimRolePlanV1,
    pub(crate) upstream_source: &'a FinalClaimSecretSourceScopeV1,
    pub(crate) downstream_source: &'a FinalClaimSecretSourceScopeV1,
    pub(crate) role_binding: &'a FinalClaimRoleBindingV1,
    pub(crate) ready: &'a OperationalM8ReadyBindingV2,
    pub(crate) policy: &'a M8TimingPolicyV1,
    pub(crate) scope: &'a BitcoinActuationScopeV1,
    pub(crate) session: &'a BitcoinClaimSessionV1,
    pub(crate) funding: &'a ProductionBitcoinFundingAuthorityV1,
    pub(crate) dom_funding_txid: [u8; 32],
    pub(crate) dom_claim_round_transcript: [u8; 32],
}

/// Borrows the already-open physical owners. The driver opens no key vault,
/// Contracts Store, actuator or second RPC client.
pub(crate) struct BitcoinPostAnchorResourcesV8<'a, 'owner> {
    pub(crate) relay: &'a mut ProductionRelayStage12OwnerV1,
    pub(crate) scanner: &'a ProductionDomF7ScannerAuthorityV1,
    pub(crate) participant: &'a mut ProductionBitcoinParticipantAuthorityV1<'owner>,
    pub(crate) actuator: &'a mut DurableBitcoinActuatorV1,
    pub(crate) bitcoin: &'a BitcoinCoreRpcClientV1,
    pub(crate) transport: &'a mut dyn BitcoinClaimTransportV6,
}

/// Public post-anchor inputs for a child whose funding and claim session are
/// already retained. The caller cannot replace that child's session, Core
/// client, actuator, readiness owner or funding custody.
#[derive(Clone, Copy)]
pub(crate) struct BitcoinPostAnchorCallV11 {
    pub(crate) route_id: [u8; 32],
    pub(crate) settlement_id: [u8; 32],
    pub(crate) composition_digest: [u8; 32],
}

pub(crate) struct BitcoinPostAnchorBoundRequestV11<'a> {
    pub(crate) binding: &'a crate::production_child_btc::ProductionBitcoinClaimBindingV11,
    pub(crate) role_binding: &'a FinalClaimRoleBindingV1,
    pub(crate) ready: &'a OperationalM8ReadyBindingV2,
    pub(crate) policy: &'a M8TimingPolicyV1,
    pub(crate) scope: &'a BitcoinActuationScopeV1,
    pub(crate) funding: &'a ProductionBitcoinFundingAuthorityV1,
    pub(crate) dom_funding_txid: [u8; 32],
    pub(crate) dom_claim_round_transcript: [u8; 32],
}

struct BitcoinPostAnchorNativeRequestV11<'a> {
    role_binding: &'a FinalClaimRoleBindingV1,
    ready: &'a OperationalM8ReadyBindingV2,
    policy: &'a M8TimingPolicyV1,
    scope: &'a BitcoinActuationScopeV1,
    session: &'a BitcoinClaimSessionV1,
    dom_funding_txid: [u8; 32],
    dom_claim_round_transcript: [u8; 32],
}

/// External retained owners borrowed only for the bilateral M.8 exchange.
pub(crate) struct BitcoinPostAnchorExternalResourcesV11<'a, 'owner> {
    pub(crate) relay: &'a mut ProductionRelayStage12OwnerV1,
    pub(crate) scanner: &'a ProductionDomF7ScannerAuthorityV1,
    pub(crate) participant: &'a mut ProductionBitcoinParticipantAuthorityV1<'owner>,
    pub(crate) transport: &'a mut dyn BitcoinClaimTransportV6,
}

#[must_use = "the exact claim and retained Contracts owner must reach their consumers"]
pub(crate) struct BitcoinPostAnchorCompletionV8 {
    pub(crate) claim: ProductionBitcoinClaimMaterializationAuthorityV1,
    pub(crate) contracts: ProductionContractsConsumedPostAnchorV2,
}

#[derive(Default)]
pub(crate) struct ProductionBitcoinPostAnchorDriverV8 {
    session_digest: Option<[u8; 32]>,
    contracts: Option<ProductionContractsConsumedPostAnchorV2>,
}

impl BitcoinPostAnchorRequestV8<'_> {
    pub(crate) fn authenticate(
        &self,
        leg: LegIdV1,
    ) -> Result<(u32, [u8; 32]), BitcoinPostAnchorErrorV8> {
        let source = ProductionBitcoinClaimMaterializationAuthorityV1::authenticate_session_v8(
            self.inputs,
            self.role_plan,
            self.upstream_source,
            self.downstream_source,
            leg,
            self.session,
        )
        .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?;
        ProductionBitcoinClaimMaterializationAuthorityV1::authenticate_funding_session_v9(
            self.session,
            self.funding,
        )
        .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?;
        let expected_leg = match leg {
            LegIdV1::Upstream => dom_final_claim_binding::ComposedSettlementLegV1::Upstream,
            LegIdV1::Downstream => dom_final_claim_binding::ComposedSettlementLegV1::Downstream,
        };
        if self.role_binding.route_leg() != expected_leg
            || self.role_binding.composed_role_plan_digest() != self.role_plan.digest()
            || self.role_binding.secret_source_scope_digest() != source
            || self.role_binding.session_id().0 != self.session.session_id
            || self.role_binding.settlement_id().0 != self.session.settlement_id
            || self.ready.final_claim_role_binding_digest()
                != self
                    .role_binding
                    .digest()
                    .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?
            || self.ready.m8_policy_digest()
                != self
                    .policy
                    .policy_digest()
                    .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?
            || self.dom_funding_txid == [0; 32]
            || self.dom_claim_round_transcript == [0; 32]
            || self.scope.route_id() != self.session.route_id
            || self.scope.effect_id() != self.session.effect_id
            || self.scope.fence_epoch() != self.session.fence_epoch
            || self.scope.terms_digest() != self.session.actuation_terms_digest_v11()
            || self.scope.registry_digest() != self.session.registry_digest
            || self.scope.profile_digest() != self.session.profile_digest
            || self.scope.action() != btc_actuator::BitcoinActionV1::Claim
            || self.scope.leg()
                != match leg {
                    LegIdV1::Upstream => btc_actuator::BitcoinLegV1::Upstream,
                    LegIdV1::Downstream => btc_actuator::BitcoinLegV1::Downstream,
                }
        {
            return Err(BitcoinPostAnchorErrorV8::Scope);
        }
        let deployment = self
            .inputs
            .admission()
            .bitcoin_deployment_capability(leg)
            .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?;
        let confirmations = deployment.profile().finality.min_confirmations;
        if confirmations == 0 {
            return Err(BitcoinPostAnchorErrorV8::Scope);
        }
        Ok((confirmations, deployment.deployment().genesis_hash))
    }
}

impl ProductionBitcoinPostAnchorDriverV8 {
    /// Completes both public exchanges. Every phase recollects the exact
    /// funding proof from Core, scans DOM through the child-owned runtime,
    /// validates F7 and checks the same durable consumed Contracts authority.
    /// On transport failure, keep this driver and reconnect the transport;
    /// the actuator replays its retained nonce and partial. After a process
    /// crash, a new driver recovers consumption from the reopened same Store.
    pub(crate) fn drive(
        &mut self,
        request: BitcoinPostAnchorRequestV8<'_>,
        resources: BitcoinPostAnchorResourcesV8<'_, '_>,
    ) -> Result<BitcoinPostAnchorCompletionV8, BitcoinPostAnchorErrorV8> {
        let (confirmations, genesis) = request.authenticate(resources.participant.leg())?;
        let (completion, contracts) = self.drive_native_v11(
            BitcoinPostAnchorNativeRequestV11 {
                role_binding: request.role_binding,
                ready: request.ready,
                policy: request.policy,
                scope: request.scope,
                session: request.session,
                dom_funding_txid: request.dom_funding_txid,
                dom_claim_round_transcript: request.dom_claim_round_transcript,
            },
            resources,
            confirmations,
            genesis,
        )?;
        let claim = completion
            .into_materialization(
                request.inputs,
                request.role_plan,
                request.upstream_source,
                request.downstream_source,
            )
            .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?;
        Ok(BitcoinPostAnchorCompletionV8 { claim, contracts })
    }

    pub(crate) fn drive_bound_v11(
        &mut self,
        request: BitcoinPostAnchorBoundRequestV11<'_>,
        resources: BitcoinPostAnchorResourcesV8<'_, '_>,
    ) -> Result<BitcoinPostAnchorCompletionV8, BitcoinPostAnchorErrorV8> {
        let leg = resources.participant.leg();
        let session = request.binding.session();
        request
            .binding
            .require_role(request.role_binding)
            .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?;
        ProductionBitcoinClaimMaterializationAuthorityV1::authenticate_funding_session_v9(
            session,
            request.funding,
        )
        .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?;
        if leg != request.binding.leg()
            || request.ready.final_claim_role_binding_digest()
                != request
                    .role_binding
                    .digest()
                    .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?
            || request.ready.m8_policy_digest()
                != request
                    .policy
                    .policy_digest()
                    .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?
            || request.scope.route_id() != session.route_id
            || request.scope.effect_id() != session.effect_id
            || request.scope.fence_epoch() != session.fence_epoch
            || request.scope.terms_digest() != session.actuation_terms_digest_v11()
            || request.scope.registry_digest() != session.registry_digest
            || request.scope.profile_digest() != session.profile_digest
            || request.scope.action() != btc_actuator::BitcoinActionV1::Claim
            || request.scope.leg()
                != match leg {
                    LegIdV1::Upstream => btc_actuator::BitcoinLegV1::Upstream,
                    LegIdV1::Downstream => btc_actuator::BitcoinLegV1::Downstream,
                }
            || request.dom_funding_txid == [0; 32]
            || request.dom_claim_round_transcript == [0; 32]
        {
            return Err(BitcoinPostAnchorErrorV8::Scope);
        }
        let (confirmations, genesis) = request.funding.post_anchor_network_v11();
        if confirmations == 0 {
            return Err(BitcoinPostAnchorErrorV8::Scope);
        }
        let (completion, contracts) = self.drive_native_v11(
            BitcoinPostAnchorNativeRequestV11 {
                role_binding: request.role_binding,
                ready: request.ready,
                policy: request.policy,
                scope: request.scope,
                session,
                dom_funding_txid: request.dom_funding_txid,
                dom_claim_round_transcript: request.dom_claim_round_transcript,
            },
            resources,
            confirmations,
            genesis,
        )?;
        let claim = completion
            .into_prepared_materialization_v11(request.binding)
            .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?;
        Ok(BitcoinPostAnchorCompletionV8 { claim, contracts })
    }

    fn drive_native_v11(
        &mut self,
        request: BitcoinPostAnchorNativeRequestV11<'_>,
        resources: BitcoinPostAnchorResourcesV8<'_, '_>,
        confirmations: u32,
        genesis: [u8; 32],
    ) -> Result<
        (
            crate::production_chain_signers::ProductionBitcoinCompletedClaimV3,
            ProductionContractsConsumedPostAnchorV2,
        ),
        BitcoinPostAnchorErrorV8,
    > {
        let leg = resources.participant.leg();
        let digest = request
            .session
            .session_digest()
            .map_err(|_| BitcoinPostAnchorErrorV8::Scope)?;
        if self
            .session_digest
            .is_some_and(|previous| previous != digest)
        {
            return Err(BitcoinPostAnchorErrorV8::Scope);
        }
        self.session_digest = Some(digest);
        let mut refusal = None;
        let completion = resources
            .participant
            .drive_claim_v6(
                resources.actuator,
                request.scope,
                request.session,
                |participant| {
                    let fresh = (|| {
                        let evidence = BitcoinCoreEvidenceCollectorV1::new(resources.bitcoin)
                            .collect_confirmed(request.session.funding_txid, confirmations)
                            .map_err(BitcoinPostAnchorErrorV8::Funding)?;
                        if evidence.txid() != request.session.funding_txid
                            || evidence.genesis_hash() != genesis
                        {
                            return Err(BitcoinPostAnchorErrorV8::Scope);
                        }
                        let verified = resources
                            .scanner
                            .verify_f7_route_anchor_authority_v2(
                                f7_anchor_authority::F7AnchorValidationRequestV2 {
                                    final_claim_role_binding: request.role_binding,
                                    ready_binding: request.ready,
                                    timing_policy: request.policy,
                                    expected_dom_funding_txid: request.dom_funding_txid,
                                    expected_bitcoin_funding_txid: request.session.funding_txid,
                                    expected_dom_claim_round_start_transcript_hash: request
                                        .dom_claim_round_transcript,
                                    bitcoin_funding_block_height: evidence.block_height(),
                                    canonical_bitcoin_funding_block: evidence
                                        .canonical_block_bytes(),
                                    bitcoin_ancestry_headers: evidence.ancestry_headers(),
                                    bitcoin_confirmation_headers: evidence.confirmation_headers(),
                                },
                            )
                            .map_err(|error| BitcoinPostAnchorErrorV8::F7(error.into()))?;
                        let (contracts, bitcoin) =
                            select_local_f7_authorization_v8(verified, participant, leg)
                                .map_err(BitcoinPostAnchorErrorV8::F7)?;
                        if let Some(retained) = &self.contracts {
                            retained
                                .refresh_with_f7_v8(contracts)
                                .map_err(BitcoinPostAnchorErrorV8::Contracts)?;
                        } else {
                            self.contracts = Some(
                                resources
                                    .relay
                                    .leg_mut(leg)
                                    .contracts_mut()
                                    .consume_or_resume_post_anchor_v8(contracts)
                                    .map_err(BitcoinPostAnchorErrorV8::Contracts)?,
                            );
                        }
                        let (local, _) = bitcoin.into_parts();
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_err(|_| BitcoinPostAnchorErrorV8::Clock)?;
                        let now_ms = u64::try_from(now.as_millis())
                            .map_err(|_| BitcoinPostAnchorErrorV8::Clock)?;
                        Ok((local, now_ms))
                    })();
                    fresh.map_err(|error| {
                        refusal = Some(error);
                        BitcoinActuatorErrorV1::ClaimAuthorityMismatch
                    })
                },
                resources.transport,
            )
            .map_err(|error| refusal.unwrap_or(BitcoinPostAnchorErrorV8::Exchange(error)))?;
        let contracts = self
            .contracts
            .take()
            .ok_or(BitcoinPostAnchorErrorV8::Scope)?;
        Ok((completion, contracts))
    }
}
